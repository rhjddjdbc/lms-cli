# Makefile for the LMS-CLI Tool

CC = gcc
CFLAGS = -Wall -O2 -std=c11
LDFLAGS =

# Directories
SRCDIR = src/c
HDRDIR = src/h
OBJDIR = src/o

# Source files
SOURCES = \
    $(SRCDIR)/main.c \
    $(SRCDIR)/sha256.c \
    $(SRCDIR)/lm_ots.c \
    $(SRCDIR)/lms.c \
    $(SRCDIR)/utils.c \
    $(SRCDIR)/bundle.c

# Object files (automatically derived from SOURCES)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# Final executable name
TARGET = lms-cli

# Default target
all: $(TARGET)

# Link all object files into the executable
$(TARGET): $(OBJECTS) | $(OBJDIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile rule: .c → .o
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(HDRDIR) -c $< -o $@

# Create object directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Header dependencies (helps make detect changes in .h files)
$(OBJDIR)/main.o:   $(HDRDIR)/sha256.h $(HDRDIR)/lm_ots.h $(HDRDIR)/lms.h $(HDRDIR)/utils.h $(HDRDIR)/bundle.h
$(OBJDIR)/sha256.o: $(HDRDIR)/sha256.h
$(OBJDIR)/lm_ots.o: $(HDRDIR)/lm_ots.h $(HDRDIR)/sha256.h
$(OBJDIR)/lms.o:    $(HDRDIR)/lms.h $(HDRDIR)/lm_ots.h $(HDRDIR)/sha256.h
$(OBJDIR)/utils.o:  $(HDRDIR)/utils.h
$(OBJDIR)/bundle.o: $(HDRDIR)/bundle.h $(HDRDIR)/lm_ots.h $(HDRDIR)/lms.h $(HDRDIR)/utils.h

# Clean up generated files
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Declare phony targets (not real files)
.PHONY: all clean
