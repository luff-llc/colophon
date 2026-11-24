// `sessionFrameText` on adversarial messages: the frame's original bytes when the message is one strict JSON object
// with exactly one top-level `frame`, and nothing otherwise.
import { describe, expect, test } from 'bun:test';
import { sessionFrameText } from '../src/hosts/index.js';

const F = '{"a":"x\\"}y","b":[1,-2.5e3,true,false,null,{}],"c":"\\u00e9\\n"}';

describe('sessionFrameText', () => {
  const kept: [string, string, string][] = [
    ['first', `{"frame":${F},"type":"session"}`, F],
    ['last', `{"type":"session","n":3,"frame":${F}}`, F],
    ['whitespace everywhere', ` \n{ "type" : "session" ,\t"frame"\r\n:  ${F}  }\n`, F],
    ['a string frame', '{"type":"session","frame":"a\\"b"}', '"a\\"b"'],
    ['an escaped quote before it', `{"x":"\\"frame\\":1","frame":${F}}`, F],
    ['"frame" inside a nested object', `{"x":{"frame":1},"frame":${F}}`, F],
    ['"frame" inside a string', `{"x":"{\\"frame\\":{}}","frame":${F}}`, F],
    ['unicode escapes in other members', `{"x":"\\ud83d\\ude00\\u0000","frame":${F}}`, F],
    ['spacing inside the frame kept', '{"frame":{ "k" : [ 1 , 2 ] }}', '{ "k" : [ 1 , 2 ] }'],
  ];
  for (const [name, message, frame] of kept) test(`keeps the frame's bytes: ${name}`, () => { expect(sessionFrameText(message)).toBe(frame); });

  const refused: [string, string][] = [
    ['an invalid bare token after it', '{"frame":{},"x":wat}'],
    ['an invalid token in it', '{"frame":{"a":tru}}'],
    ['a bad number', '{"frame":{"a":01}}'],
    ['a bad escape', '{"frame":{"a":"\\x"}}'],
    ['a short unicode escape', '{"frame":{"a":"\\u12"}}'],
    ['a raw control character', '{"frame":{"a":"\u0001"}}'],
    ['two frames', `{"frame":${F},"frame":${F}}`],
    ['two frames, one spelt with an escape', `{"frame":${F},"fr\\u0061me":{}}`],
    ['trailing data', `{"frame":${F}}x`],
    ['two objects', `{"frame":${F}}{}`],
    ['an unclosed object', `{"frame":${F}`],
    ['a trailing comma', `{"frame":${F},}`],
    ['no frame', '{"type":"session"}'],
    ['frame only nested', '{"x":{"frame":{}}}'],
    ['an array', `[${F}]`],
    ['empty', ''],
    ['nesting past the bound', `{"frame":${'['.repeat(80)}${']'.repeat(80)}}`],
  ];
  for (const [name, message] of refused) test(`refuses: ${name}`, () => { expect(sessionFrameText(message)).toBeUndefined(); });
});
