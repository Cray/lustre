# SPDX-License-Identifier: GPL-2.0-only
#
# Convert the YAML header in the first comment block of a subtest file
# (see README-ltsh.md) into "path<TAB>value" lines, where path joins the
# nested keys with ".".  A "[a, b]" list becomes "a b", while "- item"
# lists and "|" text keep their lines, joined with "\n".  Problems are
# printed with an "_error" path.
#
# usage: awk -f ltsh.awk $TESTSUITE.d/test_NNN.ltsh
#
# For sanity.d/test_230i.ltsh this prints, with <TAB> between the fields:
#
#   keywords<TAB>lmv dne migrate
#   requires.mdtcount<TAB>2
#   subtests.230i.summary<TAB>lfs migrate -m tolerates trailing slashes
#   subtests.230i.commit<TAB>e110f9ed6ea5 ("LU-7576 ...")\n169738e30a7e ...
#   subtests.230i.requires.mds1_version<TAB>v2_11_55-8-g169738e30a7e
#   subtests.230i.requires.reason<TAB>directory migration
#
function trim(s) {
	sub(/^[ \t]+/, "", s)
	sub(/[ \t]+$/, "", s)
	return s
}
function scalar(s,	c, i, out) {
	c = substr(s, 1, 1)
	if (c == "\"") {
		i = index(substr(s, 2), c)
		if (i > 0)
			return substr(s, 2, i - 1)
	} else if (c == squote) {
		# '' is a quote inside a single-quoted value
		s = substr(s, 2)
		while ((i = index(s, squote)) > 0) {
			out = out substr(s, 1, i - 1)
			if (substr(s, i + 1, 1) != squote)
				return out
			out = out squote
			s = substr(s, i + 2)
		}
		return c out s
	}
	sub(/[ \t]+#.*$/, "", s)
	return s
}
# Return why plain value s is not valid YAML, or "" if it is
function needs_quote(s) {
	if (s ~ /^["\047]/)
		return ""
	sub(/[ \t]+#.*$/, "", s)
	if (s ~ /:([ \t]|$)/)
		return "has \": \""
	if (s ~ /^[`*&!%@{|>]/)
		return "starts with \"" substr(s, 1, 1) "\""
	return ""
}
function flow(s,	n, i, a, v, out) {
	n = split(substr(s, 2, length(s) - 2), a, ",")
	for (i = 1; i <= n; i++) {
		v = scalar(trim(a[i]))
		if (v != "")
			out = out (out == "" ? "" : " ") v
	}
	return out
}
function path(	i, p) {
	for (i = 1; i <= depth; i++)
		p = p (i == 1 ? "" : ".") key[i]
	return p
}
function emit(p, v) {
	if (!(p in val))
		order[++count] = p
	val[p] = v
}
function error(msg) {
	emit("_error" NR, "line " NR ": " msg)
}
function flush_block() {
	if (block == "")
		return
	emit(block, text)
	block = ""
}
BEGIN { squote = "\047" }
!/^#/ { exit }
{
	line = $0
	sub(/^# ?/, "", line)
}
state == 0 { if (line ~ /^---[ \t]*$/) state = 1; next }
state == 2 { next }
line ~ /^(---|\.\.\.)[ \t]*$/ { flush_block(); state = 2; next }
block != "" {
	match(line, /^ */)
	if (line ~ /^[ \t]*$/) {
		blank++
		next
	}
	if (RLENGTH > block_ind) {
		if (dedent < 0)
			dedent = RLENGTH
		if (text != "") {
			# "|" keeps blank lines, ">" makes them a line break
			if (sep == " " && blank)
				text = text "\\n"
			else
				for (i = 0; i <= (sep == " " ? 0 : blank); i++)
					text = text sep
		}
		blank = 0
		text = text substr(line, dedent + 1)
		next
	}
	flush_block()
}
line ~ /^[ \t]*(#.*)?$/ { next }
{
	match(line, /^ */)
	ind = RLENGTH
	s = substr(line, ind + 1)
	if (s ~ /^-([ \t]|$)/) {
		while (depth > 0 && indent[depth] > ind)
			depth--
		sub(/^-[ \t]*/, "", s)
		s = trim(s)
		if ((why = needs_quote(s)) != "")
			error("quote \"" s "\", which " why)
		s = scalar(s)
		p = path()
		emit(p, (p in val && val[p] != "") ? val[p] "\\n" s : s)
		next
	}
	while (depth > 0 && indent[depth] >= ind)
		depth--
	if (!match(s, /:([ \t]|$)/)) {
		error("expected \"key: value\", not \"" s "\"")
		next
	}
	key[++depth] = scalar(trim(substr(s, 1, RSTART - 1)))
	indent[depth] = ind
	v = trim(substr(s, RSTART + 1))
	if (v ~ /^#/)
		v = ""
	if (v ~ /^\[/)
		sub(/\][ \t]+#.*$/, "]", v)
	if (v == "")
		next
	if (v ~ /^[|>][-+]?$/) {
		block = path()
		block_ind = ind
		dedent = -1
		sep = v ~ /^\|/ ? "\\n" : " "
		text = ""
		blank = 0
	} else if (v ~ /^\[.*\]$/) {
		emit(path(), flow(v))
	} else if (v ~ /^[[{]/) {
		error("unsupported flow value \"" v "\"")
	} else if ((why = needs_quote(v)) != "") {
		error("quote \"" v "\", which " why)
	} else {
		emit(path(), scalar(v))
	}
	depth--
}
END {
	flush_block()
	if (state == 0)
		emit("_error", "no YAML header found")
	for (i = 1; i <= count; i++)
		printf("%s\t%s\n", order[i], val[order[i]])
}
