#[cfg(any(feature = "strict-fips", feature = "fips-status"))]
use crate::error::Unspecified;

/// # Errors
/// * Unspecified
#[cfg(any(feature = "strict-fips", feature = "fips-status"))]
#[allow(clippy::module_name_repetitions)]
pub fn fips_health_status() -> Result<(), Unspecified> {
    #[allow(unused_mut)]
    let mut status = true;

    #[cfg(feature = "fips-status")]
    {
        status = status && callback::is_healthy();
    }

    #[cfg(feature = "strict-fips")]
    {
        status = status && strict::is_poisoned();
    }

    status.then(|| ()).ok_or(Unspecified)
}

#[cfg(feature = "fips-status")]
mod callback {
    use std::{
        ffi::c_char,
        sync::atomic::{AtomicBool, Ordering},
    };

    static mut FIPS_HEALTH: AtomicBool = AtomicBool::new(true);

    #[no_mangle]
    extern "C" fn AWS_LC_fips_failure_callback(_error: *const c_char) {
        unsafe {
            FIPS_HEALTH.store(false, Ordering::Release);
        }
    }

    pub fn is_healthy() -> bool {
        unsafe { FIPS_HEALTH.load(Ordering::Acquire) }
    }
}

#[cfg(feature = "strict-fips")]
pub(crate) mod strict {
    use std::sync::atomic::{AtomicBool, Ordering};

    static mut POISONED: AtomicBool = AtomicBool::new(false);

    pub fn is_poisoned() -> bool {
        unsafe { POISONED.load(Ordering::Acquire) }
    }

    pub fn set_poisoned() {
        unsafe { POISONED.store(true, Ordering::Release) }
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

#[non_exhaustive]
#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum ServiceIndicator<OUTPUT> {
    Approved(OUTPUT),
    #[allow(dead_code)]
    NotApproved(OUTPUT),
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
                #[cfg(feature = "strict-fips")]
                {
                    crate::fips::strict::set_poisoned();
                    crate::fips::ServiceIndicator::NotApproved(result)
                }
                #[cfg(not(feature = "strict-fips"))]
                {
                    crate::fips::ServiceIndicator::Approved(result)
                }
            } else {
                crate::fips::ServiceIndicator::Approved(result)
            }
        }
        #[cfg(not(feature = "fips"))]
        {
            let result = $function;
            crate::fips::ServiceIndicator::Approved(result)
        }
    }};
}

pub(crate) use indicator_check;
