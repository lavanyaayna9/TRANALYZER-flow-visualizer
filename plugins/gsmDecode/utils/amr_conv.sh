#!/usr/bin/env bash
#
# Convert AMR file(s) to MP3, OGA or WAV.
# Merge two mono AMR files into one stereo MP3, OGA or WAV file.

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] <FILE>\n\n"
    printf "Optional arguments:\n"
    printf "    -s      Convert the output to stereo (requires two input files)\n"
    printf "    -o fmt  Output format: mp3, oga, wav [default: wav]\n"
    printf "    -v      Verbose mode\n"
    printf "    -h      Display this help, then exit\n"
}

FILES=()
OUTFRMT="wav"

while [ $# -gt 0 ]; do
    case "$1" in
        -s)
            STEREO=1
            ;;
        -o)
            case "$2" in
                mp3|oga|wav)
                    OUTFRMT="$2"
                    ;;
                *)
                    printerr "Unrecognized format '$2' for '$1' option"
                    abort_with_help
                    ;;
            esac
            shift
            ;;
        -y|--yes)
            YES="yes"
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        -h|-\?|--help)
            usage
            exit 0
            ;;
        *)
            if [ ! -f "$1" ]; then
                abort_option_unknown "$1"
            else
                if [ ! "$(file -b --mime-type "$1" | grep -Fw "audio/amr")" ]; then
                    printwrn "'$1' is not a valid AMR file"
                else
                    FILES+=("$($READLINK -f "$1")")
                fi
            fi
            ;;
    esac
    shift
done

check_dependency ffmpeg

if [ ${#FILES} -eq 0 ]; then
    printerr "At least one input file is required"
    abort_with_help
elif [ $STEREO ] && [ ${#FILES[@]} -ne 2 ]; then
    printerr "Conversion to stereo requires exactly two input files"
    abort_with_help
fi

FFMPEG_OPTS=()
[ $YES ] && FFMPEG_OPTS+=(-y)

if [ $STEREO ]; then
    file0="${FILES[0]}"
    file1="${FILES[1]}"
    out0="$(replace_suffix "$file0" .amr "_")"
    out1="$(replace_suffix "$(basename "$file1")" .amr "_stereo.$OUTFRMT")"
    out="${out0}${out1}"
    log="$(replace_suffix "$out" ".$OUTFRMT" .log)"
    log="/tmp/$(basename "$log")"
    if [ -f "$out" ]; then
        ask_default_yes "File '$out' already exists... overwrite" "$YES" || continue
        rm -f "$out"
    fi
    [ $VERBOSE ] && printinf "Running ffmpeg ${FFMPEG_OPTS[@]} -i \"$file0\" -i \"$file1\" -filter_complex \"[0:a][1:a]join=inputs=2:channel_layout=stereo[a]\" -map \"[a]\" \"$out\""
    ffmpeg "${FFMPEG_OPTS[@]}" -i "$file0" -i "$file1" \
        -filter_complex "[0:a][1:a]join=inputs=2:channel_layout=stereo[a]" \
        -map "[a]" "$out" 2> "$log" \
    || printerr "Failed to convert '$file0' and '$file1': $(cat "$log")"
    rm -f "$log"
else
    for i in ${FILES[@]}; do
        out="$(replace_suffix "$i" .amr ".$OUTFRMT")"
        log="$(replace_suffix "$out" ".$OUTFRMT" .log)"
        log="/tmp/$(basename "$log")"
        if [ -f "$out" ]; then
            ask_default_yes "File '$out' already exists... overwrite" "$YES" || continue
            rm -f "$out"
        fi
        [ $VERBOSE ] && printinf "Running ffmpeg ${FFMPEG_OPTS[@]} -i \"$i\" \"$out\""
        ffmpeg "${FFMPEG_OPTS[@]}" -i "$i" "$out" 2> "$log" || printerr "Failed to convert '$i': $(cat "$log")"
        rm -f "$log"
    done
fi
