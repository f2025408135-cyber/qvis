with open("frontend/index.html", "r") as f:
    content = f.read()

content = content.replace("<style>", "<style nonce=\"{{ csp_nonce }}\">")
content = content.replace("<script ", "<script nonce=\"{{ csp_nonce }}\" ")
content = content.replace("<script>", "<script nonce=\"{{ csp_nonce }}\">")

with open("frontend/index.html", "w") as f:
    f.write(content)
