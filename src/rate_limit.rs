use once_cell::sync::OnceCell;
use dashmap::DashMap;
use std::{
    sync::Mutex, 
    net::IpAddr,
    time::{Instant, Duration},
};

#[derive(Debug)]
pub struct EndpointAccess {
    pub reg: Instant,
    pub create_account: Instant,
}

impl EndpointAccess {
    pub fn new() -> Self {
        let inst = Instant::now().checked_sub(Duration::from_secs(3600*24*256)).unwrap();
        EndpointAccess {
            reg: inst.clone(),
            create_account: inst,
        }
    }

    pub fn now_reg() -> Self {
        let mut res = Self::new();
        res.reg = Instant::now();
        res
    }

    pub fn now_create_account() -> Self {
        let mut res = Self::new();
        res.create_account = Instant::now();
        res
    }

    pub fn update_reg(&mut self) {
        self.reg = Instant::now();
    }

    pub fn update_create_account(&mut self) {
        self.create_account = Instant::now();
    }
}

static IP_HIST: OnceCell<Mutex<DashMap<IpAddr, EndpointAccess>>> = OnceCell::new();

pub fn ip_hist() -> &'static Mutex<DashMap<IpAddr, EndpointAccess>> {
    IP_HIST.get_or_init(|| Mutex::new(DashMap::new()))
}