import re
with open("backend/main.py", "r") as f:
    content = f.read()

content = content.replace("response = templates.TemplateResponse(\n        \"index.html\",\n        {\"request\": request, \"csp_nonce\": nonce}\n    )", "response = templates.TemplateResponse(\n        request=request,\n        name=\"index.html\",\n        context={\"request\": request, \"csp_nonce\": nonce}\n    )")

with open("backend/main.py", "w") as f:
    f.write(content)
