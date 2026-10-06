//! Retry only transactions with a definitive YDB ABORTED outcome.
//! Unknown commit results are never replayed automatically.

use anyhow::{Result, bail};
use std::{future::Future, time::Duration};
use ydb_grpc::ydb_proto::status_ids::StatusCode;

pub(crate) async fn retry_known_abort<T, F, Fut>(mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ydb::YdbResultWithCustomerErr<T>>,
{
    for attempt in 0..16u64 {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(
                    &error,
                    ydb::YdbOrCustomerError::YDB(ydb::YdbError::YdbStatusError(status))
                        if status.operation_status().is_ok_and(|code| code == StatusCode::Aborted)
                ) && attempt < 15 =>
            {
                tokio::time::sleep(Duration::from_millis(5 * (attempt + 1))).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("YDB transaction abort retry limit exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn status_error(code: StatusCode) -> ydb::YdbOrCustomerError {
        let mut status = ydb::YdbStatusError::default();
        status.operation_status = code as i32;
        ydb::YdbError::YdbStatusError(status).into()
    }

    #[tokio::test]
    async fn only_definitive_abort_is_retried() -> Result<()> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let value = retry_known_abort(|| {
            let attempts = attempts.clone();
            async move {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(status_error(StatusCode::Aborted))
                } else {
                    Ok(7)
                }
            }
        })
        .await?;
        assert_eq!(value, 7);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let attempts = Arc::new(AtomicUsize::new(0));
        let result = retry_known_abort(|| {
            let attempts = attempts.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(status_error(StatusCode::Undetermined))
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
