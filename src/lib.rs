mod serde_glue;
mod utils;

use gloo_utils::format::JsValueSerdeExt;
use hickory_proto::{
    error::ProtoResult,
    op::Message,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use serde_glue::MyMessage;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    utils::set_panic_hook();
}

#[wasm_bindgen]
pub fn decode(data: &[u8]) -> Result<JsValue, JsValue> {
    let mut decoder = BinDecoder::new(data);
    let decode_result: ProtoResult<Message> = Message::read(&mut decoder);

    // Handle decoding result
    match decode_result {
        Ok(message) => Ok(JsValue::from_serde(&MyMessage::serdeify(message)).unwrap()),
        Err(e) => Err(JsValue::from_str(&format!("Decoding error: {:?}", e))),
    }
}

#[wasm_bindgen]
pub fn encode(msg: JsValue) -> Result<Vec<u8>, JsValue> {
    let msg: MyMessage = serde_wasm_bindgen::from_value(msg).unwrap();
    let message = MyMessage::into_proto(msg);

    let mut buffer: Vec<u8> = vec![];
    let mut encoder = BinEncoder::new(&mut buffer);

    match message.emit(&mut encoder) {
        Ok(_) => Ok(buffer),
        Err(e) => Err(JsValue::from_str(&format!("Encoding error: {:?}", e))),
    }
}
