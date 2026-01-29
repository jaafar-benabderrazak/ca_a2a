#!/usr/bin/env python3
"""Download GitHub user-attachments images with redirect following."""

import os
import requests
from pathlib import Path

IMAGES_DIR = Path(r"C:\Users\Utilisateur\Desktop\Obsidian\finances\CA_A2A_Documentation\images")
IMAGES_DIR.mkdir(parents=True, exist_ok=True)

# Map of GitHub asset ID -> local filename
IMAGES = {
    "8776d817-a274-418f-83c6-2a2f0879b063": "production_architecture.png",
    "12587382-31da-4bf5-a5f3-cbeb4179bb7a": "aws_infrastructure.png",
    "f175345c-646c-40a7-ba88-e316b9cacc71": "protocol_comparison.png",
    "0399c2d4-7c73-4365-8d3c-47d75ebe13e3": "protocol_encapsulation.png",
    "673e6017-03f2-46d4-9d14-218f7baf2453": "defense_in_depth.png",
    "066e2291-6967-413f-b039-6f24b7be8921": "security_layers_overview.png",
    "e1fe5aee-1ffa-45f9-947a-c34074c031bb": "security_layer_details.png",
    "928e0379-e52e-453b-ac0c-182beb7dd97d": "complete_request_flow.png",
    "528e12eb-9c36-4443-b868-c12aa546cf89": "rbac_policy.png",
    "c45e0abb-0783-47c8-bdf1-22dd3ae0744c": "authorization_flow.png",
    "0fed7195-4acb-4c88-9ce3-39f12c1918f4": "token_binding_overview.png",
    "e0468375-2814-4d61-8627-2aa406b8694f": "token_binding_architecture.png",
    "0c5aeac2-7910-40d1-ba04-947c467db381": "schema_validation_flow.png",
    "838d21d1-741f-42bd-860d-4318dd03e609": "attack_prevention_examples.png",
    "6715706c-3587-4b1f-b794-557823b6a4f8": "vpc_architecture.png",
    "e938c312-f7e9-425e-82c2-ec488610f548": "security_groups.png",
    "a03e0ba2-4543-414f-9fac-0217a2ec01d3": "rate_limiting.png",
    "7f44f9ef-2203-4569-b353-ef9128c26b2a": "token_lifecycle.png",
    "68ddc83a-e0cc-43a9-821f-9c379b28f348": "cloudwatch_dashboard.png",
    "64f9fb54-6927-465c-a9c8-4014dd3d82c9": "path_traversal_defense.png",
    "f4445bc9-9590-47ef-b2bc-f129e789af1b": "base_agent_handler.png",
    "199bb585-39e0-4c2e-ab1f-8434976afeb4": "e2e_request_timeline.png",
}

def download_image(asset_id: str, filename: str) -> bool:
    """Download a single image from GitHub user-attachments."""
    url = f"https://github.com/user-attachments/assets/{asset_id}"
    output_path = IMAGES_DIR / filename
    
    print(f"Downloading {filename}...", end=" ", flush=True)
    
    try:
        # Use a browser-like User-Agent to avoid blocks
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "image/*,*/*;q=0.8",
        }
        
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=30)
        response.raise_for_status()
        
        # Check if we got an image
        content_type = response.headers.get("Content-Type", "")
        if "image" in content_type or len(response.content) > 1000:
            with open(output_path, "wb") as f:
                f.write(response.content)
            print(f"OK ({len(response.content)} bytes)")
            return True
        else:
            print(f"FAILED (not an image: {content_type})")
            return False
            
    except Exception as e:
        print(f"FAILED ({e})")
        return False

def main():
    print(f"Downloading {len(IMAGES)} images to {IMAGES_DIR}\n")
    
    success = 0
    failed = 0
    
    for asset_id, filename in IMAGES.items():
        if download_image(asset_id, filename):
            success += 1
        else:
            failed += 1
    
    print(f"\nDone! Success: {success}, Failed: {failed}")
    
    if failed > 0:
        print("\nNote: GitHub user-attachments may require browser authentication.")
        print("Alternative: Open each URL in browser and save manually.")

if __name__ == "__main__":
    main()

