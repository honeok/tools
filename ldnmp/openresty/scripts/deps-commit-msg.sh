#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 honeok <i@honeok.com>
#                           <honeok7@gmail.com>

set -eE

generate_commit_msg() {
    local DYNAMIC_CATEGO

    if git diff --quiet && git diff --cached --quiet; then
        return
    fi

    # 动态提取变动的目录名: 获取路径 -> 提取父目录名 -> 排序去重 -> 转换为空间分隔字符串
    # example: ldnmp/openresty/edge/Dockerfile -> edge
    DYNAMIC_CATEGO="$(git diff --name-only | xargs -n1 dirname | xargs -n1 basename | sort -u | xargs)"

    # 执行解析逻辑并交付格式化成果
    git diff -U0 | grep -E "^\+\+\+ b/|[-+]ARG " | awk -v categories_string="$DYNAMIC_CATEGO" '
    # 动态识别当前文件所属的逻辑分类
    /^\+\+\+ b\// {
        path_segments_count = split($0, path_segments, "/")
        current_category = path_segments[path_segments_count - 1]
        next
    }

    # 变量与版本解析
    {
        diff_symbol = substr($1, 1, 1)
        # 按照双引号分割行内容以提取版本值
        split($0, content_fragments, "\"")
        variable_definition_part = content_fragments[1]
        version_value = content_fragments[2]

        # 提取并清洗变量键名
        variable_key = variable_definition_part
        sub(/^[-+]ARG /, "", variable_key)
        sub(/[= ]+$/, "", variable_key)

        # 将旧版本与新版本映射至对应的分类关联数组
        if (diff_symbol == "-") {
            old_versions_map[current_category, variable_key] = version_value
        } else {
            new_versions_map[current_category, variable_key] = version_value
        }
    }

    # 结果渲染
    END {
        categories_count = split(categories_string, categories_order, " ")
        is_first_section = 1

        for (iterator = 1; iterator <= categories_count; iterator++) {
            target_category = categories_order[iterator]
            is_first_item_in_category = 1

            for (map_index in old_versions_map) {
                # 解析关联数组的多维索引
                split(map_index, index_parts, SUBSEP)
                category_name = index_parts[1]
                variable_name = index_parts[2]

                if (category_name == target_category) {
                    # 过滤冗余的补丁版本变量仅保留核心版本变动
                    if (variable_name ~ /PATCH_VERSION/) {
                        continue
                    }

                    if (is_first_item_in_category) {
                        # 若非首个展示的分段则添加换行符以增强可读性
                        if (!is_first_section) {
                            printf "\n"
                        }
                        printf "%s:\n", target_category
                        is_first_item_in_category = 0
                        is_first_section = 0
                    }

                    old_version_string = old_versions_map[map_index]
                    new_version_string = new_versions_map[map_index]

                    if (length(old_version_string) > 20) {
                        old_version_string = substr(old_version_string, 1, 8)
                    }
                    if (length(new_version_string) > 20) {
                        new_version_string = substr(new_version_string, 1, 8)
                    }

                    printf "- Updates `%s` from %s to %s\n", variable_name, old_version_string, new_version_string
                }
            }
        }
    }'
}

generate_commit_msg
