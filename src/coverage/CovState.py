import re
import time

class CovState:
    def __init__(self):
        self.merged_cov = {
            "br_cov": {},
            "cond_cov": {}
        }
        self.line_cov = ""

    def save_cov_data(self):
        with open("log/longtime_data/br_cov_boom.log", "w") as f:
            f.write(str(self.merged_cov))

    
    def cal_state_cov(coverage_data):
        for key, value in enumerate(coverage_data):
            print(key)
            print(value)

    # def cal_single_elf_cov:
        
    def merge_coverage_data(self, merged_cov_datas, line_cov_data):
        """
        合并多个 coverage_data 中的 br_cov 和 cond_cov 使用按位或操作。

        Args:
            results (list): 包含多个 coverage_data 的列表。
                            每个 coverage_data 是一个字典，包含 "br_cov" 和 "cond_cov"。

        Returns:
            dict: 合并后的 coverage_data 格式类似于单个 coverage_data。
        """
        for coverage_data in merged_cov_datas:
            if not coverage_data:
                continue  # 跳过空或 None 的数据

            for key in ["br_cov", "cond_cov"]:
                for index, value in coverage_data[key].items():
                    # 如果该 index 不存在于合并结果中，则直接赋值
                    if index not in self.merged_cov[key]:
                        self.merged_cov[key][index] = value
                    else:
                        # 按位或操作，合并字符串
                        self.merged_cov[key][index] = "".join(
                            "1" if a == "1" or b == "1" else "0"
                            for a, b in zip(self.merged_cov[key][index], value)
                        )

        """ 合并line cov """
        self.line_cov = line_cov_data


    def print_merge_cov(self):
        print(self.merged_cov)

    def compute_coverage(self, start_time):

        # handle br and cond cov
        ones_br     = 0
        onezeros_br = 0
        ones_cond   = 0
        onezeros_cond = 0

        for index, value in self.merged_cov['br_cov'].items():
            ones_br += value.count('1')
            onezeros_br += len(value)
        
        for index, value in self.merged_cov['cond_cov'].items():
            ones_cond += value.count('1')
            onezeros_cond += len(value)
        
        if start_time != None:
            time_now = time.time()
            m, s = divmod(time_now - start_time, 60)
            h, m = divmod(m, 60)
            print(f"Time elaps: {int(h):02}:{int(m):02}:{int(s):02}")
        
        # 如果在进行line_cov的测试 这里就跳过0
        if onezeros_br != 0:
            print(f"br_cov:   {ones_br   / onezeros_br:.5f} ({ones_br}/{onezeros_br})"    )
            print(f"cond_cov: {ones_cond / onezeros_cond:.5f} ({ones_cond}/{onezeros_cond})"  )

        # handle line cov
        inside = self.line_cov.split(")")[0].strip("(")  # "6544/30366"
        num1, num2 = map(int, inside.split("/"))
        print(f"line_cov: {num1 / num2:.5f} ({num1}/{num2})"  )

def collect_coverage(covstr: str):
    """
    解析覆盖率数据字符串并返回包含 br_cov 和 cond_cov 信号的字典。

    参数:
        covstr (str): 包含覆盖率数据的字符串。
    
    返回:
        dict: 包含 br_cov 和 cond_cov 的字典，格式如下：
              {
                  "br_cov": {0: "1000 位字符串", 1: "1000 位字符串", ...},
                  "cond_cov": {0: "1000 位字符串", 1: "1000 位字符串", ...}
              }
    """
    # 正则表达式匹配信号名称和对应的值
    pattern = r"((br_cov|cond_cov)(\d+))\s*=\s*([01]+)"
    matches = re.findall(pattern, covstr)

    # 初始化结果字典
    coverage_data = {
        "br_cov": {},
        "cond_cov": {}
    }

    # 遍历匹配结果
    for full_match, signal_type, index, value in matches:
        index = int(index)  # 将编号转换为整数

        coverage_data[signal_type][index] = value

    # 排序信号编号
    coverage_data["br_cov"] = dict(sorted(coverage_data["br_cov"].items()))
    coverage_data["cond_cov"] = dict(sorted(coverage_data["cond_cov"].items()))

    return coverage_data