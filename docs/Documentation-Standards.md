# GNAT Documentation Standards

## Purpose

This document defines how documentation is structured and maintained in GNAT using the Diátaxis model.

## The Diátaxis Model

- Tutorials → learning by doing
- How-to → solving a task
- Reference → exact technical details
- Explanation → design rationale

Each document must have ONE primary purpose.

## Directory Structure

docs/
  tutorials/
  how-to/
  reference/
  explanation/
    architecture/
      adrs/

## Rules

- Do not mix doc types
- Link instead of duplicating
- Reference is the source of truth
- Use ADRs for architectural decisions

## Guiding Principle

Documentation should match user intent.
