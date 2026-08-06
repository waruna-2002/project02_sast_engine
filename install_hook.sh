#!/bin/bash
# 1-Click Automated Git Pre-Commit Hook Installer

HOOK_PATH=".git/hooks/pre-commit"

if [ ! -d ".git" ]; then
    echo "❌ Error: Not a git repository. Run 'git init' first!"
    exit 1
fi

echo "Installing SAST Pre-commit Security Hook..."

cat << 'EOF' > $HOOK_PATH
#!/bin/bash
echo "🔍 [DevSecOps Gate] Scanning staged code changes..."
python3 core/cli.py --path . --threshold HIGH

if [ $? -ne 0 ]; then
    echo "❌ Commit Blocked: Code contains Security Violations! Fix them and try again."
    exit 1
fi
EOF

chmod +x $HOOK_PATH
echo "✅ SAST Pre-commit Security Gate installed successfully in $HOOK_PATH!"