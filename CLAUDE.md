# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a static academic personal website for Prof. Yue Duan, hosted via GitHub Pages at yueduan.github.io. Built on the Start Bootstrap Resume template (v4.0.0-beta.2) with Bootstrap 4, jQuery, and custom CSS.

## Development

No build system or package manager. To preview locally, open any `.html` file in a browser or use a local server (e.g., `python3 -m http.server`). The site is deployed automatically by GitHub Pages on push to `main`.

**CSS note:** The site loads `css/resume.min.css` (the minified version). When editing styles, update `css/resume.css` (the source) and keep `css/resume.min.css` in sync. Both files exist and are committed.

## Architecture

- **Top-level HTML pages** — each is a standalone page with its own copy of the navbar and script includes:
  - `index.html` — homepage (bio, news, openings, sponsors)
  - `pub.html` — publications
  - `lab.html` — lab members
  - `teaching.html` — teaching
  - `services.html` — professional services
  - `honors.html` — selected honors
- **`course_materials/`** — course-specific pages (CS527 Software Security, CS450 Operating Systems, CS558 Advanced Computer Security), each in its own subfolder
- **`css/resume.css`** — all custom styles (colors, layout, section labels, sponsor logos, responsive tweaks). Primary brand color is `rgb(197, 55, 55)` (red)
- **`js/resume.js`** — minimal jQuery for smooth scrolling and scrollspy
- **`vendor/`** — vendored third-party libraries (Bootstrap, Font Awesome, devicons, jQuery easing, simple-line-icons). Do not modify these
- **`img/`** — profile photo and sponsor logos (`img/logos/`)
- **`paper/`** — PDF papers linked from pub.html

## Key Conventions

- Every HTML page duplicates the full navbar and head/script boilerplate. When adding nav items or changing shared resources, update **all** HTML pages.
- Section labels use `<span class="section-label section-label-{color}">` with color variants defined in `resume.css` (red, blue, green, purple, orange, teal).
- News items on index.html are reverse-chronological. Older items are hidden behind a "More" button using inline JS toggle.
