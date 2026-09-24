CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c11
SRC_DIR = src
DEMO_DIR = demo

SRCS = $(SRC_DIR)/proc_reader.c $(SRC_DIR)/rule_engine.c $(SRC_DIR)/treatment.c \
       $(SRC_DIR)/analysis.c $(SRC_DIR)/history.c $(SRC_DIR)/graph.c \
       $(SRC_DIR)/incident.c $(SRC_DIR)/whatif.c $(SRC_DIR)/cli.c

.PHONY: all clean

all: process_ward make_patients

process_ward: $(SRCS)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(SRCS)

make_patients: $(DEMO_DIR)/make_patients.c
	$(CC) $(CFLAGS) -o $@ $(DEMO_DIR)/make_patients.c

clean:
	rm -f process_ward make_patients
