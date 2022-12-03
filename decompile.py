import requests
from bs4 import BeautifulSoup
import re


def decompile(source):
    r = requests.post('https://ethervm.io/decompile', data={'bytecode': source})
    return r.text

def decompileDeployed(address):
    r = requests.get('https://ethervm.io/decompile/' + address)
    soup = BeautifulSoup(r.text, 'html.parser')
    arr =  soup.find_all('div', class_='code javascript')
    assert(len(arr) == 1)
    t = arr[0].text
    return t

def split_functions(code: str):
    result = dict()
    lines = code.split('\n')
    i = 1
    currfun = ""
    while i < len(lines):
        line = lines[i]
        if line.startswith('    function'):
            funname = re.search('function (.*)\(', line).group(1)
            currfun = line + '\n'
            i += 1
            while not lines[i].startswith('    }'):
                currfun += lines[i] + '\n'
                i += 1
            currfun += lines[i]
            result[funname] = currfun
        i += 1
    return result

def main_anal(main_src: str):
    result = dict()
    lines = main_src.split('\n')
    i = 1
    while i < len(lines):
        line = lines[i]
        if 'if (var0 == 0x' in line:
            idx = line.index('if (var0 == 0x') + len('if (var0 == 0x')
            fourbyte = line[idx:idx+8]
            # print(fourbyte)
            i += 1
            dispatchcode = ""
            brac = 1
            while True:
                line = lines[i]
                flag = False
                for c in line:
                    if c == '{':
                        brac += 1
                    elif c == '}':
                        brac -= 1
                        if brac == 0:
                            flag = True
                            break
                if flag:
                    break
                else:
                    dispatchcode += line + '\n'
                    i += 1
            result[fourbyte] = dispatchcode
        else:
            i += 1
    return result

def find_calls(lines):
    found = []
    sanitized = ""
    for line in lines.split('\n'):
        if "//" not in line:
            sanitized += line + "\n"

    calls = re.findall("([a-zA-Z0-9_]*)\(([a-zA-Z0-9_\, ]*)\)", sanitized)

    return [i for i,_ in calls]

def table_inlining(table: dict, fourbyte: str):
    dispatch = table[fourbyte]
    # dependencies = set()
    # RIP
    # calls = find_calls(dispatch)

    dependencies = ''
    for func, body in table.items():
        if "main" not in func:
            dependencies += f"function {func}(){{ {body}\n }}\n"

    gpt_code = "contract Contract {\n" + dependencies + "     function main() {\n" + dispatch + "\n    }\n}"
    print(gpt_code)
    # print(dispatch)


# def dependency_graph(func):


def main():
    # t = decompile('0x6060604052341561000f57600080fd5b604051602080610149833981016040528080519060200190919050505b806000819055505b505b6101a88061005a6000396000f30060606040526000357c01000')
    # t = decompile("608060405234801561001057600080fd5b506004361061002b5760003560e01c80636d4ce63c14610030575b600080fd5b61003861004e565b604051610045919061011b565b60405180910390f35b60606040518060400160405280600b81526020017f48656c6c6f20576f726c64000000000000000000000000000000000000000000815250905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156100c55780820151818401526020810190506100aa565b60008484015250505050565b6000601f19601f8301169050919050565b60006100ed8261008b565b6100f78185610096565b93506101078185602086016100a7565b610110816100d1565b840191505092915050565b6000602082019050818103600083015261013581846100e2565b90509291505056fea264697066735822122060d589c0326dc8c65fc912551940071d46baa60a7a71c31b811b740531ee629964736f6c63430008110033")
    # t = decompileDeployed('0x949a6ac29b9347b3eb9a420272a9dd7890b787a3')
    # t = decompileDeployed('goerli/0x7C8C21927530f3776F6C057B71E408D88ABbb881')
    # t = decompileDeployed('goerli/0x138B359b8239B85793D8749De2C055b4e57e8958')
    t = decompileDeployed('goerli/0x773E6AA19BAB7bc35F49f6ced6fd6109F775B949')
    functions = split_functions(t)
    disp_table = main_anal(functions['main'])
    table_inlining(disp_table, "013cf08b")

main()
