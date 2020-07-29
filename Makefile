# SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: MIT

lint:
	@/bin/echo "[Kyber-K2SO] Running golangci-lint..."
	@golangci-lint run

test:
	@go clean -testcache
	@/bin/echo "[Kyber-K2SO] Running test battery..."
	@go test .

clean:
	@/bin/echo -n "[Kyber-K2SO] Cleaning up..."
	@$(RM) build/kyberk2so.*
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all windows linux macos freebsd lint test release clean assets
