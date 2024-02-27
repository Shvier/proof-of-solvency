use ark_std::fmt;

pub enum Error {

}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Error")
            .finish()
    }
}
