# IEEE/ACM 会议论文 LaTeX 模板

这是一个基于IEEE会议论文格式的LaTeX模板，适用于计算机科学、网络安全等领域的学术论文写作。

## 文件说明

- `paper_template.tex` - 主LaTeX文档模板
- `references.bib` - BibTeX参考文献数据库
- `figures/` - 存放图片文件的目录（需要自己创建）

## 模板特点

- ✅ 双栏IEEE会议格式
- ✅ US Letter页面尺寸 (8.5 x 11 英寸)
- ✅ 完整的章节结构（引言、背景、方法、评估、讨论、结论）
- ✅ 图表示例（Figure和Table）
- ✅ BibTeX参考文献管理
- ✅ 超链接支持
- ✅ 算法环境
- ✅ 中文注释便于理解

## 使用方法

### 1. 编译论文

使用以下命令编译LaTeX文档：

```bash
# 方法一：使用pdflatex + bibtex
pdflatex paper_template.tex
bibtex paper_template
pdflatex paper_template.tex
pdflatex paper_template.tex

# 方法二：使用latexmk（推荐，自动处理依赖）
latexmk -pdf paper_template.tex

# 方法三：使用xelatex（如果需要更好的中文支持）
xelatex paper_template.tex
bibtex paper_template
xelatex paper_template.tex
xelatex paper_template.tex
```

### 2. 修改模板内容

#### 标题和作者
```latex
\title{Your Paper Title Here}
\author{...}  % 修改作者信息
```

#### 摘要
在 `\begin{abstract}...\end{abstract}` 中填写你的摘要。

#### 添加章节
模板已包含常用章节结构，你可以根据需要添加或删除章节。

#### 插入图片
```latex
\begin{figure}[t]
    \centering
    \includegraphics[width=0.9\columnwidth]{figures/your_image.pdf}
    \caption{图片说明}
    \label{fig:your_label}
\end{figure}
```

注意：
- 需要创建 `figures/` 目录存放图片
- 推荐使用PDF或EPS格式的矢量图
- 使用 `\ref{fig:your_label}` 来引用图片

#### 插入表格
```latex
\begin{table}[t]
\centering
\caption{表格标题}
\label{tab:your_label}
\begin{tabular}{@{}lcc@{}}
\toprule
列1 & 列2 & 列3 \\
\midrule
数据1 & 数据2 & 数据3 \\
\bottomrule
\end{tabular}
\end{table}
```

#### 引用参考文献

1. 在 `references.bib` 中添加文献条目
2. 在正文中使用 `\cite{key}` 引用

示例：
```latex
这个问题已经被研究过~\cite{example1}。
多个引用~\cite{example1, example2, example3}。
```

### 3. 常用LaTeX命令

```latex
% 章节
\section{标题}
\subsection{子标题}
\subsubsection{子子标题}

% 列表
\begin{itemize}
    \item 项目1
    \item 项目2
\end{itemize}

\begin{enumerate}
    \item 第一项
    \item 第二项
\end{enumerate}

% 强调
\textbf{粗体}
\textit{斜体}
\texttt{等宽字体}

% 引用
\ref{label}      % 引用章节、图表等
\cite{key}       % 引用参考文献

% 数学公式
行内公式：$E = mc^2$
独立公式：
\begin{equation}
    E = mc^2
    \label{eq:einstein}
\end{equation}

% 代码
\begin{verbatim}
code here
\end{verbatim}
```

## 匿名审稿版本

如果投稿需要双盲评审（匿名），注释掉作者信息：

```latex
% \author{
% ...
% }
```

替换为：

```latex
\author{Anonymous Submission}
```

并删除致谢部分中的身份信息。

## 所需LaTeX包

模板使用了以下常用包，确保你的LaTeX发行版已安装：

- `IEEEtran` - IEEE论文类
- `cite` - 引用管理
- `amsmath, amssymb, amsfonts` - 数学符号
- `graphicx` - 图片插入
- `hyperref` - 超链接
- `booktabs` - 专业表格
- `algorithm, algorithmic` - 算法环境

## 推荐LaTeX编辑器

- **Overleaf** - 在线LaTeX编辑器（推荐新手）
- **TeXstudio** - 跨平台桌面编辑器
- **VS Code** + LaTeX Workshop插件
- **TeXShop** (Mac)
- **WinEdt** (Windows)

## 页面尺寸说明

- 默认：US Letter (8.5 x 11 英寸)
- 如需改为A4，修改 `geometry` 包设置：
  ```latex
  \usepackage[a4paper, margin=0.75in]{geometry}
  ```

## 字数统计

使用 `texcount` 工具统计字数：

```bash
texcount paper_template.tex
```

## 常见问题

### 1. 编译错误：找不到图片
确保图片路径正确，并且创建了 `figures/` 目录。

### 2. 参考文献不显示
需要运行完整的编译流程（pdflatex → bibtex → pdflatex × 2）。

### 3. 中文显示问题
如果需要在论文中使用中文，添加：
```latex
\usepackage{xeCJK}
\setCJKmainfont{SimSun}  % 或其他中文字体
```
并使用 `xelatex` 编译。

### 4. 图片跨双栏
使用 `figure*` 环境：
```latex
\begin{figure*}[t]
    ...
\end{figure*}
```

## 投稿前检查清单

- [ ] 标题和作者信息正确
- [ ] 摘要完整（150-250词）
- [ ] 所有图表都有标题和引用
- [ ] 参考文献格式统一
- [ ] 检查拼写和语法
- [ ] 页数符合会议要求
- [ ] 匿名审稿要求（如适用）
- [ ] PDF编译成功，无错误

## 参考资源

- [IEEE Author Center](https://ieeeauthorcenter.ieee.org/)
- [LaTeX Wikibook](https://en.wikibooks.org/wiki/LaTeX)
- [Overleaf Documentation](https://www.overleaf.com/learn)
- [BibTeX格式说明](http://www.bibtex.org/)

## 许可证

此模板基于IEEE模板修改，供学术写作使用。
