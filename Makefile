# netscope - 패킷 수집·분석 프로그램

CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall -Wextra -std=gnu11
CPPFLAGS += -Iinclude
LDLIBS   += -lutil -lm

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
HDR := $(wildcard include/*.h)

.PHONY: all clean dist check

all: netscope

netscope: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c $(HDR) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# 검증 스크립트 (root 권한 필요, tests/README.md 참고)
check:
	sudo tests/verify.sh

clean:
	rm -rf build netscope

# 제출용 소스 압축 (빌드 산출물, pcap 파일 제외)
DIR := $(notdir $(CURDIR))

dist: clean
	cd .. && rm -f netscope-src.zip && zip -qr netscope-src.zip $(DIR)/Makefile $(DIR)/README.md $(DIR)/.gitignore $(DIR)/include $(DIR)/src $(DIR)/tests
