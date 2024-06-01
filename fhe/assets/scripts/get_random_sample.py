import sys
import pandas as pd

from random import randint
from pathlib import Path

if __name__ == "__main__":
    path_str = sys.argv[1]
    path = Path(path_str)

    if not path.exists():
        print("File does not exists. Exiting...")
        sys.exit(-1)

    df = pd.read_csv(path_str, header=None)
    rows, cols = df.shape

    row_idx = randint(0, rows - 1)
    row = df.iloc[row_idx, :].to_list()
    row_data = row[:-1]
    row_class = int(row[-1])

    with open(f"sample_{row_idx}_{row_class}.in","w") as F:
        F.writelines(l + "\n" for l in map(str, row_data))

