#!/usr/bin/env python3

import json


def generate_readme(keys_file="keys.json"):
    with open(keys_file, "r") as file:
        data = json.load(file)

    lines = []
    header = data["content"]["header"]
    footer = data["content"]["footer"]

    lines.append(f"![Windows XP Logo]({header['logo']})")
    lines.append("")
    lines.append(header["intro"])
    lines.append("")
    lines.append(header["description"])
    lines.append("")
    lines.append(f"![Windows XP Setup]({header['setup_image']})")
    lines.append("")

    for edition in data["editions"].values():
        lines.append(f"# {edition['name']}")
        lines.append("")

        for category in edition["categories"].values():
            if category["name"] != "Default":
                lines.append(f"## {category['name']}")
                lines.append("")

            for key in category["keys"]:
                lines.append(f"- {key}")

            lines.append("")

    lines.append(f"# {footer['title']}")
    lines.append("")
    lines.append(footer["vol_explanation"])
    lines.append("")
    lines.append(footer["vlk_explanation"])
    lines.append("")
    lines.append(footer["license_info"])

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    readme_content = generate_readme()

    with open("README.md", "w") as output_file:
        output_file.write(readme_content)

    print("Generated README.md")
