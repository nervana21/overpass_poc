#!/bin/bash
set -e  # Exit on error

echo "Cleaning previous builds..."
rm -rf wasm/pkg frontend/src/pkg

echo "Building WASM bindings..."
cd wasm
wasm-pack build --target web
cd ..

echo "Creating pkg directory in frontend..."
mkdir -p frontend/src/pkg/

echo "Copying WASM package to frontend..."
cp -r wasm/pkg/* frontend/src/pkg/

# Create. index.ts in pkg directory for better imports
cat > frontend/src/pkg/index.ts << EOF
export * from './overpass_wasm'
export { default } from './overpass_wasm'
EOF

echo "Starting development server..."
cd frontend
npm run dev
cd ..
