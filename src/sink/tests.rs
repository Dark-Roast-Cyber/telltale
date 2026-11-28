#[cfg(all(test, not(windows)))]
mod delivery;

#[cfg(test)]
mod platform;
