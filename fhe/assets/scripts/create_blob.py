import sys

if __name__ == "__main__":
    cc = sys.argv[1]
    ct = sys.argv[2]
    sk = sys.argv[3]

    var = ["CC_ser", "CT_ser", "SK_ser"]
    val = [cc,ct,sk]

    with open("blob.js","w") as F:
        for i in range(3):
            data = open(val[i]).read().strip()
            F.write(f"export const {var[i]} = `{data}`;\n")
