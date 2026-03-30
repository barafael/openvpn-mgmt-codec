//! Event type for categorizing decoded messages as responses or notifications.

use crate::message::{Notification, OvpnMessage};

/// A management-interface event, categorized as either a command response
/// or an asynchronous notification.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementEvent {
    /// A command response: [`OvpnMessage::Success`], [`OvpnMessage::Error`],
    /// [`OvpnMessage::MultiLine`], [`OvpnMessage::Pkcs11IdEntry`],
    /// [`OvpnMessage::Info`], [`OvpnMessage::PasswordPrompt`], or
    /// [`OvpnMessage::Unrecognized`].
    Response(OvpnMessage),

    /// A real-time notification from the daemon.
    Notification(Notification),
}

impl From<OvpnMessage> for ManagementEvent {
    fn from(msg: OvpnMessage) -> Self {
        match msg {
            OvpnMessage::Notification(notification) => Self::Notification(notification),
            other => Self::Response(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Notification;

    #[test]
    fn success_maps_to_response() {
        let msg = OvpnMessage::Success("pid=42".to_string());
        let event: ManagementEvent = msg.into();
        assert_eq!(
            event,
            ManagementEvent::Response(OvpnMessage::Success("pid=42".to_string()))
        );
    }

    #[test]
    fn notification_maps_to_notification() {
        let msg = OvpnMessage::Notification(Notification::Hold {
            text: "Waiting".to_string(),
        });
        let event: ManagementEvent = msg.into();
        assert!(matches!(
            event,
            ManagementEvent::Notification(Notification::Hold { .. })
        ));
    }

    #[test]
    fn info_maps_to_response() {
        let msg = OvpnMessage::Info("banner".to_string());
        let event: ManagementEvent = msg.into();
        assert!(matches!(
            event,
            ManagementEvent::Response(OvpnMessage::Info(_))
        ));
    }
}
