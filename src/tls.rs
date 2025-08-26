fn bytes_to_usize(bytes: &[u8], size: usize) -> Option<usize> {
    Some(match size {
        1 => bytes[0] as usize,
        2 => u16::from_be_bytes(bytes.try_into().ok()?) as usize,
        3 => {
            ((bytes[0] as usize) << 16)
                | ((bytes[1] as usize) << 8)
                | (bytes[2] as usize)
        }
        4 => u32::from_be_bytes(bytes.try_into().ok()?) as usize,
        8 => u64::from_be_bytes(bytes.try_into().ok()?) as usize,
        _ => return None,
    })
}

struct TLSMsg<'a> {
    ptr: usize,
    payload: &'a [u8]
}

impl<'a> TLSMsg<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { ptr: 0, payload }
    }

    fn pass(&mut self, size: usize) {
        self.ptr += size;
    }

    fn get_bytes(&mut self, size: usize) -> Option<&'a [u8]> {
        if size == 0 || self.ptr + size > self.payload.len() {
            return None;
        }

        let end = self.ptr + size;
        let ret = &self.payload[self.ptr..end];
        self.ptr = end;
        Some(ret)
    }

    fn get_uint(&mut self, size: usize) -> Option<usize> {
        bytes_to_usize(self.get_bytes(size)?, size)
    }

    fn get_ptr(&self) -> usize {
        self.ptr
    }
}

pub fn is_client_hello(payload: &[u8]) -> bool {
    let mut record = TLSMsg::new(payload);
    if record.get_uint(1) != Some(22) { // type
        return false;                   // not handshake
    }

    record.pass(2);                 // legacy_record_version
    record.pass(2);                 // length

    if record.get_ptr() >= payload.len() {
        return false;
    }

    let fragment = &record.payload[record.get_ptr()..]; // fragment
    if TLSMsg::new(fragment).get_uint(1) != Some(1) { // msg_type
        return false;                     // not clienthello
    }

    true
}
