with open("backend/main.py", "r") as f:
    lines = f.readlines()

del lines[555]

with open("backend/main.py", "w") as f:
    f.writelines(lines)
