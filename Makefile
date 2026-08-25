# Convenience targets for the standalone parser and Docker integration.

CC       ?= cc
CFLAGS   ?= -Wall -Wextra -Werror -O2
CPPFLAGS += -I./src

.PHONY: all test test-asan bench bench-micro clean integration docker-build docker-test payloads \
	waf-correctness waf-perf cross-waf-smoke cross-waf-quick cross-waf-full \
	cross-waf-large native-setup native-smoke native-quick native-full \
	native-large native-check native-api-setup native-api-status native-api-collect

all: tests/test_json_guard_parser tests/bench_json_guard_parser

tests/test_json_guard_parser: tests/test_json_guard_parser.c src/json_guard_parser.c \
                              src/json_guard_parser.h src/json_guard_limits.h
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/test_json_guard_parser.c src/json_guard_parser.c \
		-o tests/test_json_guard_parser

tests/bench_json_guard_parser: tests/bench_json_guard_parser.c src/json_guard_parser.c \
                               src/json_guard_parser.h src/json_guard_limits.h
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/bench_json_guard_parser.c src/json_guard_parser.c \
		-o tests/bench_json_guard_parser

# Ensure huge_string.json exists (regenerate if missing/placeholder).
payloads:
	@python3 -c "import pathlib; p=pathlib.Path('tests/payloads/huge_string.json'); \
s='x'*100000; p.write_text('{\"s\":\"%s\"}'%s); print('wrote', p, 'bytes', p.stat().st_size)"

test: payloads tests/test_json_guard_parser
	./tests/test_json_guard_parser

test-asan: payloads
	$(CC) -Wall -Wextra -Werror -g -O1 -fsanitize=address,undefined \
		$(CPPFLAGS) tests/test_json_guard_parser.c src/json_guard_parser.c \
		-o tests/test_json_guard_parser_asan
	./tests/test_json_guard_parser_asan

bench: tests/bench_json_guard_parser
	./scripts/bench_parser.sh

tests/bench_json_guard_repeat: tests/bench_json_guard_repeat.c src/json_guard_parser.c \
                               src/json_guard_parser.h src/json_guard_limits.h
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/bench_json_guard_repeat.c src/json_guard_parser.c \
		-o tests/bench_json_guard_repeat

# Median-of-15 parser micro benchmark over generated payload sizes.
bench-micro: tests/bench_json_guard_repeat
	@for mb in 0.1 1 10 20; do \
		python3 scripts/gen_large_json.py --size-mb $$mb --output /tmp/jg_micro_$${mb}m.json >/dev/null; \
		printf "%-12s " "$${mb} MiB"; \
		./tests/bench_json_guard_repeat /tmp/jg_micro_$${mb}m.json 15; \
	done

docker-build:
	docker build -f docker/Dockerfile -t ngx_json_guard:test .

docker-test integration:
	./scripts/run_docker_integration.sh

waf-correctness:
	PROFILE=correctness WORKERS=1 SMALL_REPEAT=1 LARGE_REPEAT=1 \
		./scripts/run_waf_perf.sh

waf-perf:
	PROFILE=benchmark WORKERS=4 SMALL_REPEAT=10 LARGE_REPEAT=3 \
		./scripts/run_waf_perf.sh

cross-waf-smoke:
	MODE=smoke ./scripts/run_cross_waf_bench.sh

cross-waf-quick:
	MODE=quick ./scripts/run_cross_waf_bench.sh

cross-waf-full:
	MODE=full ./scripts/run_cross_waf_bench.sh

cross-waf-large:
	./scripts/run_cross_waf_large.sh

native-check:
	python3 -m py_compile scripts/cross_waf_bench.py \
		scripts/native_host_metrics.py scripts/compare_native_hosts.py \
		benchmark/native_body_sink.py
	bash -n scripts/native_lab.sh scripts/native_api_server.sh
	python3 -m json.tool benchmark/native/engines.json >/dev/null
	python3 tests/test_native_benchmark.py

native-setup:
	sudo ./scripts/native_lab.sh setup

native-smoke:
	sudo ./scripts/native_lab.sh smoke

native-quick:
	sudo ./scripts/native_lab.sh quick

native-full:
	sudo ./scripts/native_lab.sh full

native-large:
	sudo ./scripts/native_lab.sh large

native-api-setup:
	sudo ./scripts/native_api_server.sh setup

native-api-status:
	sudo ./scripts/native_api_server.sh status

native-api-collect:
	sudo ./scripts/native_api_server.sh collect

clean:
	rm -f tests/test_json_guard_parser tests/test_json_guard_parser_asan \
		tests/bench_json_guard_parser tests/bench_json_guard_repeat
