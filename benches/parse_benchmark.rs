use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use tma_init_data::parse;

fn benchmark_parse_simple(c: &mut Criterion) {
    let init_data = "auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2&query_id=AAHdF6IQAAAAAN0XohDhrOrc";

    c.bench_function("parse_simple", |b| b.iter(|| parse(black_box(init_data))));
}

fn benchmark_parse_with_user(c: &mut Criterion) {
    let init_data = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2";

    c.bench_function("parse_with_user", |b| {
        b.iter(|| parse(black_box(init_data)))
    });
}

fn benchmark_parse_with_all_fields(c: &mut Criterion) {
    let init_data = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2&start_param=abc&can_send_after=3600&chat_type=group&chat_instance=123456789";

    c.bench_function("parse_with_all_fields", |b| {
        b.iter(|| parse(black_box(init_data)))
    });
}

criterion_group!(
    benches,
    benchmark_parse_simple,
    benchmark_parse_with_user,
    benchmark_parse_with_all_fields
);
criterion_main!(benches);
