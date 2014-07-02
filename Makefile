.DEFAULT_GOAL := all

# Variables to set through command line.
DEBUG ?= YES

# General configuration.
OUT_DIR_DEBUG := build/debug
OUT_DIR_RELEASE := build/release
OUT_DIR := $(if $(filter YES,$(DEBUG)),$(OUT_DIR_DEBUG),$(OUT_DIR_RELEASE))
OBJ_DIR := $(OUT_DIR)/obj

CCFLAGS := -MMD
ifeq ($(DEBUG),YES)
  CCFLAGS += -g -DDEBUG
endif

# Library.
LIBONEPASS_SRC := $(wildcard src/*.cc)
LIBONEPASS_OBJ := $(addprefix $(OBJ_DIR)/,$(notdir $(LIBONEPASS_SRC:.cc=.o)))
LIBONEPASS_CCFLAGS := $(CCFLAGS) -std=c++11 -Wall -Wextra -Werror

$(OBJ_DIR)/%.o: src/%.cc
	mkdir -p $(@D)
	g++ $(LIBONEPASS_CCFLAGS) -c -o $@ $<

LIBONEPASS := $(OUT_DIR)/libonepass.a
$(LIBONEPASS): $(LIBONEPASS_OBJ)
	ar -r $@ $^

-include $(LIBONEPASS_OBJ:.o=.d)

# Samples.
SAMPLE_SRC := $(wildcard sample/*.cc)
SAMPLE_OBJ := $(addprefix $(OBJ_DIR)/sample/,$(notdir $(SAMPLE_SRC:.cc=.o)))
SAMPLE_CCFLAGS := $(CCFLAGS) -Isrc/ -std=c++11 -Wall -Wextra -Werror
SAMPLE_LDFLAGS := -lcrypto

$(OBJ_DIR)/sample/%.o: sample/%.cc
	mkdir -p $(@D)
	g++ $(SAMPLE_CCFLAGS) -c -o $@ $<

SAMPLE := $(OUT_DIR)/sample
$(SAMPLE): $(SAMPLE_OBJ) $(LIBONEPASS)
	g++ $(SAMPLE_LDFLAGS) -o $@ $^ $(LIBONEPASS)

-include $(SAMPLE_OBJ:.o=.d)

# Tests.
TEST_SRC := $(wildcard test/*.cc)
TEST_OBJ := $(addprefix $(OBJ_DIR)/test/,$(notdir $(TEST_SRC:.cc=.o)))
TEST_CCFLAGS := $(CCFLAGS) -Isrc/ -std=c++11 -Wall -Wextra -Werror
TEST_LDFLAGS := -lcrypto -lgtest -lgtest_main

$(OBJ_DIR)/test/%.o: test/%.cc
	mkdir -p $(@D)
	g++ $(TEST_CCFLAGS) -c -o $@ $<

TEST := $(OUT_DIR)/test
$(TEST): $(TEST_OBJ) $(LIBONEPASS)
	g++ $(TEST_LDFLAGS) -o $@ $^ $(LIBONEPASS)

-include $(TEST_OBJ:.o=.d)

.PHONY: all clean

all: $(LIBONEPASS) $(SAMPLE) $(TEST)

clean:
	rm -Rf $(OUT_DIR)

libonepass: $(LIBONEPASS)

sample: $(SAMPLE)

test: $(TEST)
	$(OUT_DIR)/test
