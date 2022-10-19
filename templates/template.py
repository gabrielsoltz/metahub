import yaml
from pathlib import Path
conf = yaml.safe_load(Path('template.yml').read_text())
