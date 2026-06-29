#!/bin/bash -eu
#
# Build entry point for ClusterFuzzLite / OSS-Fuzz style fuzzing of ChronoSift.
#
# It compiles the ChronoSift library (core/event/syslog/weblog/jsonlog/winlog/
# analyze/pipeline) and links every harness in fuzz/ into a self-contained
# binary in $OUT, using the sanitizer and fuzzing-engine flags provided by the
# environment. All sources are referenced from the repository root, which the
# platform mounts at $SRC; there are no absolute machine paths, no network
# access, and no interactive prompts.

# Locate the repository root robustly. The platform mounts the repo at $SRC and
# runs this script from the repo root, but we do not assume either is correct:
# we pick the first candidate that actually contains the ChronoSift sources.
find_root() {
  local cand
  for cand in "${SRC:-}" "$(pwd)" "$(dirname "${BASH_SOURCE[0]:-.}")/.."; do
    [ -n "${cand}" ] || continue
    if [ -d "${cand}/src/core" ] && [ -d "${cand}/fuzz" ] \
       && [ -f "${cand}/CMakeLists.txt" ]; then
      ( cd "${cand}" && pwd )
      return 0
    fi
  done
  return 1
}

ROOT="$(find_root || true)"
if [ -z "${ROOT}" ]; then
  echo "error: could not locate ChronoSift sources (looked in \$SRC, CWD, script dir)" >&2
  exit 1
fi
cd "${ROOT}"
echo "ChronoSift build root: ${ROOT}"

# Sensible defaults so the script is also runnable from a plain developer
# checkout; in the fuzzing image these come from the environment.
: "${CXX:=clang++}"
: "${CXXFLAGS:=-O1 -g -std=c++17}"
: "${OUT:=${ROOT}/out}"
mkdir -p "${OUT}"

# Ensure C++17 is requested even if the environment's CXXFLAGS omits it.
case " ${CXXFLAGS} " in
  *" -std="*) ;;
  *) CXXFLAGS="${CXXFLAGS} -std=c++17" ;;
esac

INCLUDES="-I${ROOT}/include"

# When the fuzzing engine is not provided (developer build), fall back to the
# in-tree standalone driver so the harnesses still link into runnable binaries.
STANDALONE=""
if [ -z "${LIB_FUZZING_ENGINE:-}" ]; then
  echo "LIB_FUZZING_ENGINE not set; linking harnesses with the standalone driver."
  STANDALONE="${ROOT}/fuzz/standalone_driver.cc"
fi

# Globs that match nothing expand to nothing rather than to the literal pattern.
shopt -s nullglob

echo "Compiling ChronoSift library objects..."
OBJ_DIR="${ROOT}/.cflite_obj"
rm -rf "${OBJ_DIR}"
mkdir -p "${OBJ_DIR}"

# Compile every translation unit under src/ (any module, including ones added
# later) so the harness link never misses a symbol. find keeps this list in sync
# with the tree automatically; sort makes the build order deterministic.
LIB_OBJECTS=""
for src in $(find src -name '*.cpp' | sort); do
  [ -e "${src}" ] || continue
  obj="${OBJ_DIR}/$(echo "${src}" | tr '/' '_').o"
  echo "  CXX ${src}"
  ${CXX} ${CXXFLAGS} ${INCLUDES} -c "${src}" -o "${obj}"
  LIB_OBJECTS="${LIB_OBJECTS} ${obj}"
done

if [ -z "${LIB_OBJECTS}" ]; then
  echo "error: no library sources found under ${ROOT}/src" >&2
  exit 1
fi

echo "Linking fuzz harnesses into ${OUT}..."
built=0
for harness in fuzz/*_fuzzer.cc; do
  name="$(basename "${harness}" .cc)"
  echo "  HARNESS ${name}"
  if ! ${CXX} ${CXXFLAGS} ${INCLUDES} \
        ${LIB_FUZZING_ENGINE:-} ${STANDALONE} \
        "${harness}" ${LIB_OBJECTS} \
        -o "${OUT}/${name}"; then
    echo "error: failed to link harness ${name}" >&2
    exit 1
  fi
  built=$((built + 1))

  # Package this harness's seed corpus following the OSS-Fuzz convention so the
  # fuzzer starts from realistic, structure-bearing inputs.
  seed_dir="fuzz/corpus/${name}"
  if [ -d "${seed_dir}" ] && command -v zip >/dev/null 2>&1; then
    ( cd "${seed_dir}" && zip -q -r "${OUT}/${name}_seed_corpus.zip" . ) || true
  fi
done

shopt -u nullglob

if [ "${built}" -eq 0 ]; then
  echo "error: no fuzz harnesses found under ${ROOT}/fuzz" >&2
  exit 1
fi

echo "Build complete: ${built} harness(es) in ${OUT}:"
ls -1 "${OUT}" | sed 's/^/  /'
