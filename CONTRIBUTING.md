# 📜 Contribution Guide

Thank you for your interest in contributing to this Rust project! Follow the steps below to ensure smooth collaboration.

## 📌 Getting Started

1. **Fork the Repository**: Click the "Fork" button on GitHub to create your copy of the project.
2. **Clone Your Fork**:
   ```sh
   git clone https://github.com/bas-man/rust-decon-spf.git
   ```
3. **Set Up the Upstream Remote** (optional but recommended):
   ```sh
   git remote add upstream https://github.com/bas-man/rust-decon-spf.git
   ```

## 🛠️ Development Setup

1. **Ensure You Have Rust Installed**
    - Install Rust using [rustup](https://rustup.rs/):
      ```sh
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
      ```
    - Check your Rust version:
      ```sh
      rustc --version  # Ensure it's up to date
      ```

2. **Install Required Dependencies**
    - If the project uses `cargo`, install dependencies:
      ```sh
      cargo build
      ```
    - If additional dependencies are required, check the `README.md`.

3. **Run Tests Before Making Changes**
   ```sh
   cargo test
   ```

## 🔧 Making Changes

1. **Create a New Branch**:
   ```sh
   git checkout -b feature/your-feature-name
   ```
2. **Make Your Changes & Format Code**
    - Write clean, idiomatic Rust code.
    - Run `cargo fmt` to format your code.
    - Use `cargo clippy` to catch common mistakes:
      ```sh
      cargo clippy --all-targets --all-features
      ```

3. **Run Tests Again**
   ```sh
   cargo test
   ```

4. **Commit Your Changes**:
    - Follow conventional commit messages (e.g., `feat: add new feature`).
    - Example:
      ```sh
      git commit -m "feat: improve error handling in parser"
      ```

## 📤 Submitting a Pull Request

1. **Push Your Branch**:
   ```sh
   git push origin feature/your-feature-name
   ```
2. **Open a Pull Request** on GitHub:
    - Base branch: `master` or `dev` (check the project’s contribution rules).
    - Provide a clear description of your changes.

## ✅ Code Review and Merging

- A maintainer will review your PR.
- Address requested changes if needed.
- Once approved, it will be merged!

## 📜 License

By contributing, you agree that your code will be licensed under the project's existing license.