#[cfg(feature = "fips")]
use crate::error::Unspecified;

/// # Errors
/// * Unspecified
#[cfg(feature = "fips")]
#[allow(clippy::module_name_repetitions)]
pub fn service_status() -> Result<(), Unspecified> {
    indicator::is_degraded().then(|| ()).ok_or(Unspecified)
}

#[cfg(feature = "fips")]
pub(crate) mod indicator {
    use std::sync::atomic::{AtomicBool, Ordering};

    static mut DEGRADED: AtomicBool = AtomicBool::new(false);

    pub fn is_degraded() -> bool {
        unsafe { DEGRADED.load(Ordering::Acquire) }
    }

    pub fn set_degraded() {
        unsafe { DEGRADED.store(true, Ordering::Release) }
    }
}

#[cfg(feature = "fips")]
pub(crate) fn service_indicator_before_call() -> u64 {
    unsafe { aws_lc::FIPS_service_indicator_before_call() }
}

#[cfg(feature = "fips")]
pub(crate) fn service_indicator_after_call() -> u64 {
    unsafe { aws_lc::FIPS_service_indicator_after_call() }
}

macro_rules! indicator_check {
    ($function:expr) => {{
        #[cfg(feature = "fips")]
        {
            use crate::fips::{service_indicator_after_call, service_indicator_before_call};
            let before = service_indicator_before_call();
            let result = $function;
            let after = service_indicator_after_call();
            if !(before != after) {
                crate::fips::indicator::set_degraded();
                #[cfg(feature = "strict-fips")]
                {
                    Result::<_, crate::error::ServiceNotApproved>::Err(
                        crate::error::ServiceNotApproved,
                    )
                }
                #[cfg(not(feature = "strict-fips"))]
                {
                    Result::<_, crate::error::ServiceNotApproved>::Ok(result)
                }
            } else {
                Result::<_, crate::error::ServiceNotApproved>::Ok(result)
            }
        }
        #[cfg(not(feature = "fips"))]
        {
            let result = $function;
            Result::<_, crate::error::ServiceNotApproved>::Ok(result)
        }
    }};
}

pub(crate) use indicator_check;
