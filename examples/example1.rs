use argon2_rs::Argon2;

fn main() {
    let m_cost = 512_000;
    let t_cost = 8;
    let p_cost = 1;

    let argon2 = Argon2::new(m_cost, t_cost, p_cost);
    let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let time  = std::time::Instant::now();
    let hash = argon2.hash_password("password", salt).unwrap();
    println!("Hash: {:?}", hash);
    println!("Time to compute: {}secs", time.elapsed().as_secs_f32());   
}