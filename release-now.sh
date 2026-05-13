#!/bin/bash

# Usuwa i odtwarza release 'latest' z dzisiejszego commitu (HEAD).
# Używać gdy chcemy podbić datę taga bez publikowania nowej wersji.
# Gwiazdki repozytorium NIE są tracone — są na repo, nie na release.

REPO_DIR="/c/Projekty/github/sftp"
REPO="wesmar/sftp"
TAG="latest"
ASSET="bin/SFTPplug.zip"
ASSET_NAME="SFTPplug.zip"
NOTES_FILE="release.txt"
TITLE="v1.0.0.17"

cd "$REPO_DIR" || { echo "❌ Nie można przejść do: $REPO_DIR"; exit 1; }

if [ ! -f "$ASSET" ]; then
    echo "❌ Błąd: Nie znaleziono: $ASSET"
    echo "   Uruchom najpierw: build.ps1"
    exit 1
fi

if [ ! -f "$NOTES_FILE" ]; then
    echo "❌ Błąd: Nie znaleziono: $NOTES_FILE"
    exit 1
fi

SIZE=$(du -h "$ASSET" | cut -f1)
COMMIT=$(git log --oneline -1)
echo "======================================"
echo "📦 Asset:   $ASSET_NAME ($SIZE)"
echo "🎯 Release: $TAG @ $REPO"
echo "📝 Notes:   $NOTES_FILE"
echo "🔖 Commit:  $COMMIT"
echo "======================================"
echo ""
echo "⚠️  Usuwa i odtwarza tag '$TAG' (source code pokaże dzisiejszą datę)."
read -r -p "Kontynuować? [t/N] " confirm
[[ "$confirm" =~ ^[tTyY]$ ]] || { echo "Anulowano."; exit 0; }

echo ""
echo "======================================"
echo "🗑️  KROK 1: Usuwanie release + tag"
echo "======================================"
gh release delete "$TAG" --repo "$REPO" --yes --cleanup-tag 2>/dev/null \
    && echo "✅ Release i tag usunięte" \
    || echo "⚠️  Release nie istniało (pierwsze tworzenie)"

echo ""
echo "======================================"
echo "📤 KROK 2: Tworzenie nowego release"
echo "======================================"
gh release create "$TAG" \
    --repo "$REPO" \
    --title "$TITLE" \
    --notes-file "$NOTES_FILE" \
    "$ASSET#$ASSET_NAME"

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✅ SUKCES!"
    echo "======================================"
    echo "   https://github.com/$REPO/releases/tag/$TAG"
else
    echo "❌ Błąd tworzenia release!"
    exit 1
fi
