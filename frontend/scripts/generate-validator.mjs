import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import standaloneCode from 'ajv/dist/standalone/index.js'

const project = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const schema = JSON.parse(readFileSync(path.resolve(project, '../schemas/report-v1.schema.json'), 'utf8'))
const ajv = new Ajv2020({ strict: false, allErrors: false, code: { source: true, esm: true } })
const validate = ajv.compile(schema)
const output = standaloneCode(ajv, validate)
  .replaceAll('require("ajv/dist/runtime/ucs2length").default', 'ucs2length')
  .replaceAll('require("ajv/dist/runtime/equal").default', 'equal')
if (output.includes('require(')) throw new Error('Generated validator contains an unhandled runtime import')
writeFileSync(path.resolve(project, 'src/lib/generated/validator.js'),
  `import ucs2length from 'ajv/dist/runtime/ucs2length.js'\nimport equal from 'ajv/dist/runtime/equal.js'\n${output}`)
