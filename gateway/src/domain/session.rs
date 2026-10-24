use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub token: String,
    pub user_id: String,
    pub nickname: String,
    /// Viewed text channel; independent of the active voice room.
    pub channel_id: Option<String>,
    pub voice_channel_id: Option<String>,
}

pub type SessionStore = Arc<RwLock<HashMap<String, Session>>>;

pub fn new_store() -> SessionStore {
    Arc::new(RwLock::new(HashMap::new()))
}

pub async fn create(store: &SessionStore, user_id: String, nickname: String) -> Session {
    let s = Session {
        session_id: Uuid::new_v4().to_string(),
        token: Uuid::new_v4().to_string(),
        user_id,
        nickname,
        channel_id: None,
        voice_channel_id: None,
    };
    store.write().await.insert(s.session_id.clone(), s.clone());
    s
}

pub async fn get(store: &SessionStore, id: &str) -> Option<Session> {
    store.read().await.get(id).cloned()
}

pub async fn remove(store: &SessionStore, id: &str) {
    store.write().await.remove(id);
}

pub async fn get_session_id_by_user_id(store: &SessionStore, user_id: &str) -> Option<String> {
    store
        .read()
        .await
        .iter()
        .find(|(_, s)| s.user_id == user_id)
        .map(|(id, _)| id.clone())
}
