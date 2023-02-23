use self::{
    ibd::IbdFlow,
    ping::{ReceivePingsFlow, SendPingsFlow},
    request_headers::RequestHeadersFlow,
    request_pp_proof::RequestPruningPointProofFlow,
};
use crate::{flow_context::FlowContext, flow_trait::Flow};
use kaspa_core::debug;
use p2p_lib::{
    make_message,
    pb::{kaspad_message::Payload as KaspadMessagePayload, AddressesMessage},
    KaspadMessagePayloadType, Router,
};
use std::sync::Arc;

mod ibd;
mod ping;
mod request_headers;
mod request_pp_proof;

pub fn register(ctx: FlowContext, router: Arc<Router>) -> Vec<Box<dyn Flow>> {
    let flows: Vec<Box<dyn Flow>> = vec![
        Box::new(IbdFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                KaspadMessagePayloadType::BlockHeaders,
                KaspadMessagePayloadType::DoneHeaders,
                KaspadMessagePayloadType::IbdBlockLocatorHighestHash,
                KaspadMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
                KaspadMessagePayloadType::BlockWithTrustedDataV4,
                KaspadMessagePayloadType::DoneBlocksWithTrustedData,
                KaspadMessagePayloadType::IbdChainBlockLocator,
                KaspadMessagePayloadType::IbdBlock,
                KaspadMessagePayloadType::TrustedData,
                KaspadMessagePayloadType::PruningPoints,
                KaspadMessagePayloadType::PruningPointProof,
                KaspadMessagePayloadType::UnexpectedPruningPoint,
                KaspadMessagePayloadType::PruningPointUtxoSetChunk,
                KaspadMessagePayloadType::DonePruningPointUtxoSetChunks,
            ]),
        )),
        Box::new(ReceivePingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![KaspadMessagePayloadType::Ping]))),
        Box::new(SendPingsFlow::new(ctx.clone(), Arc::downgrade(&router), router.subscribe(vec![KaspadMessagePayloadType::Pong]))),
        Box::new(RequestHeadersFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![KaspadMessagePayloadType::RequestHeaders, KaspadMessagePayloadType::RequestNextHeaders]),
        )),
        Box::new(RequestPruningPointProofFlow::new(
            ctx,
            router.clone(),
            router.subscribe(vec![KaspadMessagePayloadType::RequestPruningPointProof]),
        )),
    ];

    // TEMP: subscribe to remaining messages and ignore them
    // NOTE: as flows are implemented, the below types should be all commented out
    let mut unimplemented_messages_route = router.subscribe(vec![
        KaspadMessagePayloadType::Addresses,
        KaspadMessagePayloadType::Block,
        KaspadMessagePayloadType::Transaction,
        KaspadMessagePayloadType::BlockLocator,
        KaspadMessagePayloadType::RequestAddresses,
        KaspadMessagePayloadType::RequestRelayBlocks,
        KaspadMessagePayloadType::RequestTransactions,
        // KaspadMessagePayloadType::IbdBlock,
        KaspadMessagePayloadType::InvRelayBlock,
        KaspadMessagePayloadType::InvTransactions,
        // KaspadMessagePayloadType::Ping,
        // KaspadMessagePayloadType::Pong,
        // KaspadMessagePayloadType::Verack,
        // KaspadMessagePayloadType::Version,
        // KaspadMessagePayloadType::Ready,
        KaspadMessagePayloadType::TransactionNotFound,
        KaspadMessagePayloadType::Reject,
        // KaspadMessagePayloadType::PruningPointUtxoSetChunk,
        KaspadMessagePayloadType::RequestIbdBlocks,
        // KaspadMessagePayloadType::UnexpectedPruningPoint,
        KaspadMessagePayloadType::IbdBlockLocator,
        // KaspadMessagePayloadType::IbdBlockLocatorHighestHash,
        KaspadMessagePayloadType::RequestNextPruningPointUtxoSetChunk,
        // KaspadMessagePayloadType::DonePruningPointUtxoSetChunks,
        // KaspadMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
        KaspadMessagePayloadType::BlockWithTrustedData,
        // KaspadMessagePayloadType::DoneBlocksWithTrustedData,
        KaspadMessagePayloadType::RequestPruningPointAndItsAnticone,
        // KaspadMessagePayloadType::BlockHeaders,
        // KaspadMessagePayloadType::RequestNextHeaders,
        // KaspadMessagePayloadType::DoneHeaders,
        KaspadMessagePayloadType::RequestPruningPointUtxoSet,
        // KaspadMessagePayloadType::RequestHeaders,
        KaspadMessagePayloadType::RequestBlockLocator,
        // KaspadMessagePayloadType::PruningPoints,
        KaspadMessagePayloadType::RequestPruningPointProof,
        // KaspadMessagePayloadType::PruningPointProof,
        // KaspadMessagePayloadType::BlockWithTrustedDataV4,
        // KaspadMessagePayloadType::TrustedData,
        KaspadMessagePayloadType::RequestIbdChainBlockLocator,
        // KaspadMessagePayloadType::IbdChainBlockLocator,
        KaspadMessagePayloadType::RequestAnticone,
        KaspadMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks,
    ]);

    tokio::spawn(async move {
        while let Some(msg) = unimplemented_messages_route.recv().await {
            // TEMP: responding to this request is required in order to keep the
            // connection live until we implement the send addresses flow
            if let Some(KaspadMessagePayload::RequestAddresses(_)) = msg.payload {
                debug!("P2P Flows, got request addresses message");
                let _ =
                    router.enqueue(make_message!(KaspadMessagePayload::Addresses, AddressesMessage { address_list: vec![] })).await;
            }
        }
    });

    flows
}
