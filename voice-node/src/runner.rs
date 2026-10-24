use crate::{Config, MAX_UDP_PACKET, secure::Relay};
use tokio::{net::UdpSocket, sync::broadcast};
use tracing::info;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let (_tx, rx) = broadcast::channel(1);
    run_bind(&config.node.name, &config.voice.bind, rx).await
}
/// Receives credentials only over the in-process gateway bridge. Standalone mode is fail-closed.
pub async fn run_bind(
    node_name: &str,
    bind: &str,
    mut events: broadcast::Receiver<String>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    info!(node=node_name,address=%socket.local_addr()?,"authenticated UDP voice listening");
    let mut relay = Relay::default();
    let mut buffer = [0u8; MAX_UDP_PACKET + 1];
    let mut bridge_open = true;
    loop {
        tokio::select! {
         event=events.recv(),if bridge_open=>match event {
          Ok(value)=>if let Ok(event)=serde_json::from_str(&value){relay.event(&event);},
          Err(broadcast::error::RecvError::Lagged(_))=>relay.clear(),
          Err(broadcast::error::RecvError::Closed)=>{relay.clear();bridge_open=false;},
         },
         result=socket.recv_from(&mut buffer)=>{
          let (len,src)=result?;
          for (addr,packet) in relay.receive(&buffer[..len],src) {let _=socket.send_to(&packet,addr).await;}
         }
        }
    }
}
