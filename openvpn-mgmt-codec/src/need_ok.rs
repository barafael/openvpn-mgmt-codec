/// Response to a `>NEED-OK:` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum NeedOkResponse {
    /// Accept the prompt.
    Ok,

    /// Reject the prompt.
    Cancel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ok() {
        assert_eq!(NeedOkResponse::Ok.to_string(), "ok");
    }

    #[test]
    fn display_cancel() {
        assert_eq!(NeedOkResponse::Cancel.to_string(), "cancel");
    }
}
