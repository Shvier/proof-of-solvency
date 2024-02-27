use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar, 
    prelude::AllocVar, 
    poly::polynomial::univariate::dense::DensePolynomialVar,
    R1CSVar,
};
use ark_relations::{r1cs::{
    ConstraintSynthesizer,
    ConstraintSystemRef,
    Result,
}, ns};

pub struct PolyTransConstraints<PF: PrimeField> {
    pub point: usize,
    pub root_of_unity: PF,
    pub scale_factor: usize,
    pub shift_factor: usize,

    pub old_coeffs: Vec<PF>,
    pub new_coeffs: Vec<PF>,
}

impl<PF> ConstraintSynthesizer<PF> for PolyTransConstraints<PF> where PF: PrimeField {
    fn generate_constraints(self, cs: ConstraintSystemRef<PF>) -> Result<()> {
        let old_var = {
            let coeffs: Vec<_> = self.old_coeffs
            .iter()
            .map(|&x| {
                FpVar::new_witness(ns!(cs, "old_coeff"), || Ok(x)).unwrap()
            })
            .collect();
            DensePolynomialVar::from_coefficients_vec(coeffs)
        };

        let new_var = {
            let coeffs: Vec<_> = self.new_coeffs
            .iter()
            .map(|&x| {
                FpVar::new_witness(ns!(cs, "new_coeff"), || Ok(x)).unwrap()
            })
            .collect();
            DensePolynomialVar::from_coefficients_vec(coeffs)
        };

        let point_var = FpVar::new_input(ns!(cs, "point"), || Ok(self.root_of_unity.pow(&[self.point as u64]))).unwrap();
        let scaled_point = self.root_of_unity.pow(&[(self.point * self.scale_factor + self.shift_factor) as u64]);
        let scaled_point_var = FpVar::new_input(ns!(cs, "new_point"), || Ok(scaled_point)).unwrap();

        let old_eval = old_var.evaluate(&scaled_point_var).unwrap();
        let new_eval = new_var.evaluate(&point_var).unwrap();

        assert_eq!(old_eval.value().unwrap(), new_eval.value().unwrap());
        assert!(cs.is_satisfied().unwrap());

        Ok(())
    }
}
