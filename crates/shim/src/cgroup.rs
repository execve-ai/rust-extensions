/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#![cfg(target_os = "linux")]

use std::{
    error::Error as StdError,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use cgroups_rs::{
    cgroup::get_cgroups_relative_paths_by_pid, error::Result as CgResult, hierarchies, Cgroup,
    CgroupPid, MaxValue, Subsystem,
};
use containerd_shim_protos::{
    cgroups::metrics::{BlkIOEntry, BlkIOStat, CPUStat, CPUUsage, MemoryEntry, MemoryStat, Metrics, PidsStat, Throttle},
    protobuf::{well_known_types::any::Any, Message},
    shim::oci::Options,
};
use oci_spec::runtime::LinuxResources;

use crate::error::{Error, Result};

// OOM_SCORE_ADJ_MAX is from https://github.com/torvalds/linux/blob/master/include/uapi/linux/oom.h#L10
const OOM_SCORE_ADJ_MAX: i64 = 1000;

#[cfg_attr(feature = "tracing", tracing::instrument(level = "Info"))]
pub fn set_cgroup_and_oom_score(pid: u32) -> Result<()> {
    if pid == 0 {
        return Ok(());
    }

    // set cgroup
    let mut data: Vec<u8> = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .map_err(io_error!(e, "read stdin"))?;

    if !data.is_empty() {
        let opts =
            Any::parse_from_bytes(&data).and_then(|any| Options::parse_from_bytes(&any.value))?;

        if !opts.shim_cgroup.is_empty() {
            add_task_to_cgroup(opts.shim_cgroup.as_str(), pid)?;
        }
    }

    // set oom score
    adjust_oom_score(pid)
}

/// Add a process to the given relative cgroup path
#[cfg_attr(feature = "tracing", tracing::instrument(level = "Info"))]
pub fn add_task_to_cgroup(path: &str, pid: u32) -> Result<()> {
    let h = hierarchies::auto();
    // use relative path here, need to trim prefix '/'
    let path = path.trim_start_matches('/');

    Cgroup::load(h, path)
        .add_task_by_tgid(CgroupPid::from(pid as u64))
        .map_err(other_error!("add task to cgroup"))
}

/// Sets the OOM score for the process to the parents OOM score + 1
/// to ensure that they parent has a lower score than the shim
#[cfg_attr(feature = "tracing", tracing::instrument(level = "Info"))]
pub fn adjust_oom_score(pid: u32) -> Result<()> {
    let score = read_process_oom_score(std::os::unix::process::parent_id())?;
    if score < OOM_SCORE_ADJ_MAX {
        write_process_oom_score(pid, score + 1)?;
    }
    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn read_process_oom_score(pid: u32) -> Result<i64> {
    let content = fs::read_to_string(format!("/proc/{}/oom_score_adj", pid))
        .map_err(io_error!(e, "read oom score"))?;
    let score = content
        .trim()
        .parse::<i64>()
        .map_err(other_error!("parse oom score"))?;
    Ok(score)
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn write_process_oom_score(pid: u32, score: i64) -> Result<()> {
    fs::write(format!("/proc/{}/oom_score_adj", pid), score.to_string())
        .map_err(io_error!(e, "write oom score"))
}

/// Collect process cgroup stats, return only necessary parts of it
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub fn collect_metrics(pid: u32) -> Result<Metrics> {
    let mut metrics = Metrics::new();

    let cgroup = get_cgroup(pid)?;

    // to make it easy, fill the necessary metrics only.
    for sub_system in Cgroup::subsystems(&cgroup) {
        match sub_system {
            Subsystem::Cpu(cpu_ctr) => {
                let mut cpu_usage = CPUUsage::new();
                let mut throttle = Throttle::new();
                let stat = cpu_ctr.cpu().stat;
                
                // Use helper function for cleaner parsing
                set_cpu_usage_and_throttle(&stat, &mut cpu_usage, &mut throttle);
                
                let mut cpu_stats = CPUStat::new();
                cpu_stats.set_throttling(throttle);
                cpu_stats.set_usage(cpu_usage);
                metrics.set_cpu(cpu_stats);
            }
            Subsystem::CpuAcct(cpuacct_ctr) => {
                // Add CpuAcct metrics support
                let acct = cpuacct_ctr.cpuacct();
                let mut cpu_usage = CPUUsage::new();
                cpu_usage.set_total(acct.usage);
                cpu_usage.set_kernel(acct.usage_sys);
                cpu_usage.set_user(acct.usage_user);
                cpu_usage.set_per_cpu(
                    acct.usage_percpu
                        .split_whitespace()
                        .map(|s| s.parse::<u64>().unwrap_or_default())
                        .collect(),
                );
                
                // Merge with existing CPU stats or create new
                let mut cpu_stat = if let Some(existing) = metrics.cpu.as_ref() {
                    existing.clone()
                } else {
                    CPUStat::new()
                };
                cpu_stat.set_usage(cpu_usage);
                metrics.set_cpu(cpu_stat);
            }
            Subsystem::BlkIo(blkio_ctr) => {
                // Add BlkIO metrics support
                let mut blkio_stat = BlkIOStat::new();
                let mut io_service_bytes_recursive: Vec<BlkIOEntry> = Vec::new();
                let blkio = blkio_ctr.blkio().io_service_bytes_recursive;
                
                for data in blkio.iter() {
                    if data.read != 0 {
                        let mut entry = BlkIOEntry::new();
                        entry.set_major(data.major as u64);
                        entry.set_minor(data.minor as u64);
                        entry.set_op("read".to_string());
                        entry.set_value(data.read);
                        io_service_bytes_recursive.push(entry);
                    }
                    if data.write != 0 {
                        let mut entry = BlkIOEntry::new();
                        entry.set_major(data.major as u64);
                        entry.set_minor(data.minor as u64);
                        entry.set_op("write".to_string());
                        entry.set_value(data.write);
                        io_service_bytes_recursive.push(entry);
                    }
                }
                blkio_stat.set_io_service_bytes_recursive(io_service_bytes_recursive);
                metrics.set_blkio(blkio_stat);
            }
            Subsystem::Mem(mem_ctr) => {
                let mut mem_stat = MemoryStat::new();

                // set memory
                let mem = mem_ctr.memory_stat();
                let mut mem_entry = MemoryEntry::new();
                mem_entry.set_usage(mem.usage_in_bytes);
                mem_entry.set_limit(mem.limit_in_bytes as u64);
                mem_entry.set_max(mem.max_usage_in_bytes);
                mem_entry.set_failcnt(mem.fail_cnt);
                mem_stat.set_usage(mem_entry);

                // set swap memory
                let memswap = mem_ctr.memswap();
                let mut memswap_entry = MemoryEntry::new();
                memswap_entry.set_usage(memswap.usage_in_bytes);
                memswap_entry.set_limit(memswap.limit_in_bytes as u64);
                memswap_entry.set_max(memswap.max_usage_in_bytes);
                memswap_entry.set_failcnt(memswap.fail_cnt);
                mem_stat.set_swap(memswap_entry);

                // set kernel memory
                let kmem = mem_ctr.kmem_stat();
                let mut kmem_entry = MemoryEntry::new();
                kmem_entry.set_usage(kmem.usage_in_bytes);
                kmem_entry.set_limit(kmem.limit_in_bytes as u64);
                kmem_entry.set_max(kmem.max_usage_in_bytes);
                kmem_entry.set_failcnt(kmem.fail_cnt);
                mem_stat.set_kernel(kmem_entry);

                // set tcp memory
                let kmem_tcp = mem_ctr.kmem_tcp_stat();
                let mut kmem_tcp_entry = MemoryEntry::new();
                kmem_tcp_entry.set_usage(kmem_tcp.usage_in_bytes);
                kmem_tcp_entry.set_limit(kmem_tcp.limit_in_bytes as u64);
                kmem_tcp_entry.set_max(kmem_tcp.max_usage_in_bytes);
                kmem_tcp_entry.set_failcnt(kmem_tcp.fail_cnt);
                mem_stat.set_kernel_tcp(kmem_tcp_entry);

                // all other detailed stats
                mem_stat.set_active_anon(mem.stat.active_anon);
                mem_stat.set_active_file(mem.stat.active_file);
                mem_stat.set_cache(mem.stat.cache);
                mem_stat.set_dirty(mem.stat.dirty);
                mem_stat.set_hierarchical_memory_limit(mem.stat.hierarchical_memory_limit as u64);
                mem_stat.set_hierarchical_swap_limit(mem.stat.hierarchical_memsw_limit as u64);
                mem_stat.set_mapped_file(mem.stat.mapped_file);
                mem_stat.set_pg_fault(mem.stat.pgfault);
                mem_stat.set_pg_maj_fault(mem.stat.pgmajfault);
                mem_stat.set_pg_pg_in(mem.stat.pgpgin);
                mem_stat.set_pg_pg_out(mem.stat.pgpgout);
                mem_stat.set_rss(mem.stat.rss);
                mem_stat.set_rss_huge(mem.stat.rss_huge);
                mem_stat.set_total_active_anon(mem.stat.total_active_anon);
                mem_stat.set_total_active_file(mem.stat.total_active_file);
                mem_stat.set_inactive_anon(mem.stat.inactive_anon);
                mem_stat.set_inactive_file(mem.stat.inactive_file);
                mem_stat.set_total_cache(mem.stat.total_cache);
                mem_stat.set_total_dirty(mem.stat.total_dirty);
                mem_stat.set_total_inactive_anon(mem.stat.total_inactive_anon);
                mem_stat.set_total_inactive_file(mem.stat.total_inactive_file);
                mem_stat.set_total_mapped_file(mem.stat.total_mapped_file);
                mem_stat.set_total_pg_fault(mem.stat.total_pgfault);
                mem_stat.set_total_pg_maj_fault(mem.stat.total_pgmajfault);
                mem_stat.set_total_pg_pg_in(mem.stat.total_pgpgin);
                mem_stat.set_total_pg_pg_out(mem.stat.total_pgpgout);
                mem_stat.set_total_rss(mem.stat.total_rss);
                mem_stat.set_total_rss_huge(mem.stat.total_rss_huge);
                mem_stat.set_total_unevictable(mem.stat.total_unevictable);
                mem_stat.set_total_writeback(mem.stat.total_writeback);
                mem_stat.set_unevictable(mem.stat.unevictable);
                mem_stat.set_writeback(mem.stat.writeback);
                metrics.set_memory(mem_stat);
            }
            Subsystem::Pid(pid_ctr) => {
                // ignore cgroup NotFound error
                let ignore_err = |cr: CgResult<u64>| -> CgResult<u64> {
                    cr.or_else(|e| {
                        if e.source()
                            .and_then(<dyn StdError>::downcast_ref::<std::io::Error>)
                            .map(std::io::Error::kind)
                            == Some(std::io::ErrorKind::NotFound)
                        {
                            Ok(0)
                        } else {
                            Err(e)
                        }
                    })
                };

                let mut pid_stats = PidsStat::new();
                pid_stats.set_current(
                    ignore_err(pid_ctr.get_pid_current())
                        .map_err(other_error!("get current pid"))?,
                );

                pid_stats.set_limit(
                    ignore_err(pid_ctr.get_pid_max().map(|val| match val {
                        // See https://github.com/opencontainers/runc/blob/dbe8434359ca35af1c1e10df42b1f4391c1e1010/libcontainer/cgroups/fs/pids.go#L55
                        cgroups_rs::MaxValue::Max => 0,
                        cgroups_rs::MaxValue::Value(val) => val as u64,
                    }))
                    .map_err(other_error!("get pid limit"))?,
                );
                metrics.set_pids(pid_stats)
            }
            _ => {}
        }
    }
    Ok(metrics)
}

// get_cgroup will return either cgroup v1 or v2 depending on system configuration
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn get_cgroup(pid: u32) -> Result<Cgroup> {
    let hierarchies = hierarchies::auto();
    let cgroup = if hierarchies.v2() {
        let path = get_cgroups_v2_path_by_pid(pid)?;
        Cgroup::load(hierarchies, path)
    } else {
        // get container main process cgroup
        let path =
            get_cgroups_relative_paths_by_pid(pid).map_err(other_error!("get process cgroup"))?;
        Cgroup::load_with_relative_paths(hierarchies::auto(), Path::new("."), path)
    };
    Ok(cgroup)
}

/// Get the cgroups v2 path given a PID
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub fn get_cgroups_v2_path_by_pid(pid: u32) -> Result<PathBuf> {
    // todo: should upstream to cgroups-rs
    let path = format!("/proc/{}/cgroup", pid);
    let content = fs::read_to_string(path).map_err(io_error!(e, "read cgroup"))?;
    let content = content.lines().next().unwrap_or("");

    let Ok(path) = parse_cgroups_v2_path(content)?.canonicalize() else {
        return Err(Error::Other("cgroup path not found".to_string()));
    };
    Ok(path)
}

// https://github.com/opencontainers/runc/blob/1950892f69597aa844cbf000fbdf77610dda3a44/libcontainer/cgroups/fs2/defaultpath.go#L83
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn parse_cgroups_v2_path(content: &str) -> Result<PathBuf> {
    // the entry for cgroup v2 is always in the format like `0::$PATH`
    // where 0 is the hierarchy ID, the controller name is omitted in cgroup v2
    // and $PATH is the cgroup path
    // see https://docs.kernel.org/admin-guide/cgroup-v2.html
    let Some(path) = content.strip_prefix("0::") else {
        return Err(Error::Other(format!("invalid cgroup path: {}", content)));
    };

    let path = path.trim_start_matches('/');

    Ok(PathBuf::from(format!("/sys/fs/cgroup/{}", path)))
}

/// Update process cgroup limits
#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
pub fn update_resources(pid: u32, resources: &LinuxResources) -> Result<()> {
    // get container main process cgroup
    let cgroup = get_cgroup(pid)?;

    for sub_system in Cgroup::subsystems(&cgroup) {
        match sub_system {
            Subsystem::Pid(pid_ctr) => {
                // set maximum number of PIDs
                if let Some(pids) = resources.pids() {
                    pid_ctr
                        .set_pid_max(MaxValue::Value(pids.limit()))
                        .map_err(other_error!("set pid max"))?;
                }
            }
            Subsystem::Mem(mem_ctr) => {
                if let Some(memory) = resources.memory() {
                    //if swap and limit setting have
                    if let (Some(limit), Some(swap)) = (memory.limit(), memory.swap()) {
                        //get current memory_limit
                        let current = mem_ctr.memory_stat().limit_in_bytes;
                        // if the updated swap value is larger than the current memory limit set the swap changes first
                        // then set the memory limit as swap must always be larger than the current limit
                        if current < swap {
                            mem_ctr
                                .set_memswap_limit(swap)
                                .map_err(other_error!("set memsw limit"))?;
                            mem_ctr
                                .set_limit(limit)
                                .map_err(other_error!("set mem limit"))?;
                        }
                    }
                    // set memory limit in bytes
                    if let Some(limit) = memory.limit() {
                        mem_ctr
                            .set_limit(limit)
                            .map_err(other_error!("set mem limit"))?;
                    }

                    // set memory swap limit in bytes
                    if let Some(swap) = memory.swap() {
                        mem_ctr
                            .set_memswap_limit(swap)
                            .map_err(other_error!("set memsw limit"))?;
                    }
                }
            }
            Subsystem::CpuSet(cpuset_ctr) => {
                if let Some(cpu) = resources.cpu() {
                    // set CPUs to use within the cpuset
                    if let Some(cpus) = cpu.cpus() {
                        cpuset_ctr
                            .set_cpus(cpus)
                            .map_err(other_error!("set CPU sets"))?;
                    }

                    // set list of memory nodes in the cpuset
                    if let Some(mems) = cpu.mems() {
                        cpuset_ctr
                            .set_mems(mems)
                            .map_err(other_error!("set CPU memes"))?;
                    }
                }
            }
            Subsystem::Cpu(cpu_ctr) => {
                if let Some(cpu) = resources.cpu() {
                    // set CPU shares
                    if let Some(shares) = cpu.shares() {
                        cpu_ctr
                            .set_shares(shares)
                            .map_err(other_error!("set CPU share"))?;
                    }

                    // set CPU hardcap limit
                    if let Some(quota) = cpu.quota() {
                        cpu_ctr
                            .set_cfs_quota(quota)
                            .map_err(other_error!("set CPU quota"))?;
                    }

                    // set CPU hardcap period
                    if let Some(period) = cpu.period() {
                        cpu_ctr
                            .set_cfs_period(period)
                            .map_err(other_error!("set CPU period"))?;
                    }
                }
            }
            Subsystem::HugeTlb(ht_ctr) => {
                // set the limit if "pagesize" hugetlb usage
                if let Some(hp_limits) = resources.hugepage_limits() {
                    for limit in hp_limits {
                        ht_ctr
                            .set_limit_in_bytes(limit.page_size().as_str(), limit.limit() as u64)
                            .map_err(other_error!("set huge page limit"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cgroups_rs::{hierarchies, Cgroup, CgroupPid};

    use super::parse_cgroups_v2_path;
    use crate::cgroup::{
        add_task_to_cgroup, adjust_oom_score, read_process_oom_score, OOM_SCORE_ADJ_MAX,
    };

    #[test]
    fn test_add_cgroup() {
        let path = "runc_shim_test_cgroup";
        let h = hierarchies::auto();

        // create cgroup path first
        let cg = Cgroup::new(h, path).unwrap();

        let pid = std::process::id();
        add_task_to_cgroup(path, pid).unwrap();
        let cg_id = CgroupPid::from(pid as u64);
        assert!(cg.tasks().contains(&cg_id));

        // remove cgroup as possible
        cg.remove_task_by_tgid(cg_id).unwrap();
        cg.delete().unwrap()
    }

    #[test]
    fn test_adjust_oom_score() {
        let pid = std::process::id();
        let score = read_process_oom_score(pid).unwrap();

        adjust_oom_score(pid).unwrap();
        let new = read_process_oom_score(pid).unwrap();
        if score < OOM_SCORE_ADJ_MAX {
            assert_eq!(new, score + 1)
        } else {
            assert_eq!(new, OOM_SCORE_ADJ_MAX)
        }
    }

    #[test]
    fn test_parse_cgroups_v2_path() {
        let path = "0::/user.slice/user-1000.slice/session-2.scope";
        assert_eq!(
            parse_cgroups_v2_path(path).unwrap(),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/session-2.scope")
        );
    }

    #[test]
    fn test_parse_cgroups_v2_path_empty() {
        let path = "0::";
        assert_eq!(
            parse_cgroups_v2_path(path).unwrap(),
            PathBuf::from("/sys/fs/cgroup/")
        );
    }

    #[test]
    fn test_parse_cgroups_v2_path_kube() {
        let path = "0::/kubepods-besteffort-pod8.slice:cri-containerd:8";
        assert_eq!(
            parse_cgroups_v2_path(path).unwrap(),
            PathBuf::from("/sys/fs/cgroup/kubepods-besteffort-pod8.slice:cri-containerd:8")
        );
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "info"))]
fn set_cpu_usage_and_throttle(stat: &str, cpu_usage: &mut CPUUsage, throttle: &mut Throttle) {
    for line in stat.lines() {
        let parts = line.split_whitespace().collect::<Vec<&str>>();
        if parts.len() == 2 {
            let value = parts[1].parse::<u64>().unwrap_or_default();
            match parts[0] {
                "usage_usec" => {
                    cpu_usage.set_total(value);
                }
                "user_usec" => {
                    cpu_usage.set_user(value);
                }
                "system_usec" => {
                    cpu_usage.set_kernel(value);
                }
                "nr_periods" => {
                    throttle.set_periods(value);
                }
                "nr_throttled" => {
                    throttle.set_throttled_periods(value);
                }
                "throttled_usec" => {
                    throttle.set_throttled_time(value);
                }
                _ => {}
            }
        }
    }
}
