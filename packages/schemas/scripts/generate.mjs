import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'

import yaml from 'js-yaml'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const packageDir = path.resolve(scriptDir, '..')
const outputPath = path.join(packageDir, 'src', 'generated', 'schemas.ts')
const openapiPath = path.join(packageDir, 'openapi.yaml')

const isRecord = value => typeof value === 'object' && value !== null && !Array.isArray(value)

const toPascalCase = value =>
  value
    .replace(/\.schema$/i, '')
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map(part => part[0].toUpperCase() + part.slice(1))
    .join('')

const loadJson = filePath => JSON.parse(fs.readFileSync(filePath, 'utf8'))

const resolveJsonPointer = (root, pointer) => {
  const segments = pointer
    .split('/')
    .filter(Boolean)
    .map(segment => segment.replace(/~1/g, '/').replace(/~0/g, '~'))

  let current = root
  for (const segment of segments) {
    if (Array.isArray(current)) {
      const index = Number(segment)
      if (Number.isNaN(index)) {
        return undefined
      }
      current = current[index]
      continue
    }

    if (!isRecord(current)) {
      return undefined
    }

    current = current[segment]
  }

  return current
}

const buildSchemaMetadata = () => {
  const standaloneFiles = fs
    .readdirSync(packageDir)
    .filter(fileName => fileName.endsWith('.schema.json'))
    .sort((a, b) => a.localeCompare(b))

  const standaloneSchemas = standaloneFiles.map(fileName => {
    const schema = loadJson(path.join(packageDir, fileName))
    const schemaName = `${toPascalCase(path.basename(fileName, '.json'))}Schema`
    return {kind: 'file', fileName, schemaName, schema}
  })

  const openapiDoc = yaml.load(fs.readFileSync(openapiPath, 'utf8'))
  if (!isRecord(openapiDoc)) {
    throw new Error('openapi.yaml did not parse into an object')
  }

  const components = isRecord(openapiDoc.components) ? openapiDoc.components : {}
  const componentSchemas = isRecord(components.schemas) ? components.schemas : {}

  const openapiSchemas = Object.entries(componentSchemas)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([schemaName, schema]) => ({
      kind: 'openapi',
      schemaName: `OpenApi${toPascalCase(schemaName)}Schema`,
      componentName: schemaName,
      schema
    }))

  return {
    standaloneSchemas,
    openapiSchemas,
    openapiDoc
  }
}

const quote = value => JSON.stringify(value)

const renderLiteralUnion = values => `z.union([${values.map(value => `z.literal(${quote(value)})`).join(', ')}])`

const renderRef = ({ref, context, maps, stack}) => {
  if (ref.startsWith('#/components/schemas/')) {
    const componentName = ref.slice('#/components/schemas/'.length)
    const resolvedName = maps.openapiByComponent.get(componentName)
    if (!resolvedName) {
      return 'z.unknown()'
    }
    return `z.lazy(() => ${resolvedName})`
  }

  if (ref.startsWith('./')) {
    const resolvedName = maps.fileByRef.get(ref)
    if (!resolvedName) {
      return 'z.unknown()'
    }
    return `z.lazy(() => ${resolvedName})`
  }

  if (ref.startsWith('#/')) {
    const localKey = `${context.source}:${ref}`
    if (stack.has(localKey)) {
      return 'z.unknown()'
    }

    const resolved = resolveJsonPointer(context.rootSchema, ref.slice(1))
    if (resolved === undefined) {
      return 'z.unknown()'
    }

    const nextStack = new Set(stack)
    nextStack.add(localKey)
    return renderSchema({schema: resolved, context, maps, stack: nextStack})
  }

  return 'z.unknown()'
}

const renderStringSchema = schema => {
  let result = 'z.string()'
  if (typeof schema.minLength === 'number') {
    result += `.min(${schema.minLength})`
  }
  if (typeof schema.maxLength === 'number') {
    result += `.max(${schema.maxLength})`
  }
  if (typeof schema.pattern === 'string') {
    result += `.regex(new RegExp(${quote(schema.pattern)}))`
  }
  if (schema.format === 'date-time') {
    result += '.datetime({offset: true})'
  } else if (schema.format === 'uri') {
    result += '.url()'
  } else if (schema.format === 'uuid') {
    result += '.uuid()'
  } else if (schema.format === 'email') {
    result += '.email()'
  }
  return result
}

const renderNumberSchema = ({schema, integer}) => {
  let result = integer ? 'z.number().int()' : 'z.number()'
  if (typeof schema.minimum === 'number') {
    result += `.gte(${schema.minimum})`
  }
  if (typeof schema.maximum === 'number') {
    result += `.lte(${schema.maximum})`
  }
  if (typeof schema.exclusiveMinimum === 'number') {
    result += `.gt(${schema.exclusiveMinimum})`
  }
  if (typeof schema.exclusiveMaximum === 'number') {
    result += `.lt(${schema.exclusiveMaximum})`
  }
  return result
}

const renderObjectSchema = ({schema, context, maps, stack}) => {
  const properties = isRecord(schema.properties) ? schema.properties : {}
  const required = new Set(
    Array.isArray(schema.required) ? schema.required.filter(name => typeof name === 'string') : []
  )
  const propertyEntries = Object.entries(properties).map(([key, propertySchema]) => {
    const propertyContext = {source: context.source, rootSchema: context.rootSchema}
    let propertyExpr = renderSchema({schema: propertySchema, context: propertyContext, maps, stack})
    if (!required.has(key)) {
      propertyExpr += '.optional()'
    }
    return `${quote(key)}: ${propertyExpr}`
  })

  let result = `z.object({${propertyEntries.join(', ')}})`

  if (schema.additionalProperties === false) {
    result += '.strict()'
  } else if (isRecord(schema.additionalProperties) || typeof schema.additionalProperties === 'boolean') {
    if (schema.additionalProperties === true) {
      result += '.loose()'
    } else if (schema.additionalProperties === false) {
      result += '.strict()'
    } else {
      result += `.catchall(${renderSchema({schema: schema.additionalProperties, context, maps, stack})})`
    }
  } else {
    result += '.loose()'
  }

  return result
}

const renderArraySchema = ({schema, context, maps, stack}) => {
  const itemSchema = schema.items ?? true
  let result = `z.array(${renderSchema({schema: itemSchema, context, maps, stack})})`
  if (typeof schema.minItems === 'number') {
    result += `.min(${schema.minItems})`
  }
  if (typeof schema.maxItems === 'number') {
    result += `.max(${schema.maxItems})`
  }
  return result
}

const applyNullable = ({schema, expression}) => (schema.nullable === true ? `${expression}.nullable()` : expression)

const renderTypedSchema = ({schema, context, maps, stack}) => {
  const rawType = schema.type
  const typeList = Array.isArray(rawType) ? rawType.filter(typeName => typeof typeName === 'string') : []
  const declaredTypes = typeList.length > 0 ? typeList : typeof rawType === 'string' ? [rawType] : []

  const hasNull = declaredTypes.includes('null')
  const baseTypes = declaredTypes.filter(typeName => typeName !== 'null')

  const renderSingleType = typeName => {
    switch (typeName) {
      case 'string':
        return renderStringSchema(schema)
      case 'integer':
        return renderNumberSchema({schema, integer: true})
      case 'number':
        return renderNumberSchema({schema, integer: false})
      case 'boolean':
        return 'z.boolean()'
      case 'null':
        return 'z.null()'
      case 'array':
        return renderArraySchema({schema, context, maps, stack})
      case 'object':
        return renderObjectSchema({schema, context, maps, stack})
      default:
        return 'z.unknown()'
    }
  }

  if (baseTypes.length === 0 && hasNull) {
    return 'z.null()'
  }

  if (baseTypes.length === 0) {
    return null
  }

  const expression =
    baseTypes.length === 1
      ? renderSingleType(baseTypes[0])
      : `z.union([${baseTypes.map(typeName => renderSingleType(typeName)).join(', ')}])`

  return hasNull ? `${expression}.nullable()` : expression
}

const renderSchema = ({schema, context, maps, stack}) => {
  if (schema === true) {
    return 'z.unknown()'
  }
  if (schema === false) {
    return 'z.never()'
  }
  if (!isRecord(schema)) {
    return 'z.unknown()'
  }

  if (typeof schema.$ref === 'string') {
    return renderRef({ref: schema.$ref, context, maps, stack})
  }

  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    if (schema.enum.every(value => typeof value === 'string')) {
      return `z.enum([${schema.enum.map(value => quote(value)).join(', ')}])`
    }
    return renderLiteralUnion(schema.enum)
  }

  if (Object.prototype.hasOwnProperty.call(schema, 'const')) {
    return `z.literal(${quote(schema.const)})`
  }

  if (Array.isArray(schema.oneOf) && schema.oneOf.length > 0) {
    return `z.union([${schema.oneOf.map(item => renderSchema({schema: item, context, maps, stack})).join(', ')}])`
  }

  if (Array.isArray(schema.anyOf) && schema.anyOf.length > 0) {
    return `z.union([${schema.anyOf.map(item => renderSchema({schema: item, context, maps, stack})).join(', ')}])`
  }

  if (Array.isArray(schema.allOf) && schema.allOf.length > 0) {
    const {allOf, ...schemaWithoutAllOf} = schema
    const parts = []

    if (Object.keys(schemaWithoutAllOf).length > 0) {
      parts.push(renderSchema({schema: schemaWithoutAllOf, context, maps, stack}))
    }

    for (const item of allOf) {
      const itemExpr = renderSchema({schema: item, context, maps, stack})
      if (itemExpr !== 'z.unknown()') {
        parts.push(itemExpr)
      }
    }

    if (parts.length === 0) {
      return 'z.unknown()'
    }

    const combined = parts.slice(1).reduce((acc, part) => `${acc}.and(${part})`, parts[0])
    return applyNullable({schema, expression: combined})
  }

  const typed = renderTypedSchema({schema, context, maps, stack})
  if (typed) {
    return applyNullable({schema, expression: typed})
  }

  if (isRecord(schema.properties)) {
    return renderObjectSchema({schema, context, maps, stack})
  }

  return applyNullable({schema, expression: 'z.unknown()'})
}

const generate = () => {
  const {standaloneSchemas, openapiSchemas} = buildSchemaMetadata()

  const fileByRef = new Map(standaloneSchemas.map(item => [`./${item.fileName}`, item.schemaName]))
  const openapiByComponent = new Map(openapiSchemas.map(item => [item.componentName, item.schemaName]))
  const maps = {fileByRef, openapiByComponent}

  const lines = [
    '/* eslint-disable */',
    '// This file is auto-generated by scripts/generate.mjs. Do not edit manually.',
    "import {z} from 'zod'",
    ''
  ]

  for (const schemaDef of standaloneSchemas) {
    const context = {source: `file:${schemaDef.fileName}`, rootSchema: schemaDef.schema}
    const expression = renderSchema({schema: schemaDef.schema, context, maps, stack: new Set()})
    const typeName = schemaDef.schemaName.replace(/Schema$/, '')
    lines.push(`export const ${schemaDef.schemaName} = ${expression}`)
    lines.push(`export type ${typeName} = z.infer<typeof ${schemaDef.schemaName}>`)
    lines.push('')
  }

  for (const schemaDef of openapiSchemas) {
    const context = {source: 'openapi', rootSchema: schemaDef.schema}
    const expression = renderSchema({schema: schemaDef.schema, context, maps, stack: new Set()})
    const typeName = schemaDef.schemaName.replace(/Schema$/, '')
    lines.push(`export const ${schemaDef.schemaName} = ${expression}`)
    lines.push(`export type ${typeName} = z.infer<typeof ${schemaDef.schemaName}>`)
    lines.push('')
  }

  lines.push('export const schemaRegistry = {')
  for (const schemaDef of standaloneSchemas) {
    lines.push(`  ${schemaDef.schemaName}: ${schemaDef.schemaName},`)
  }
  for (const schemaDef of openapiSchemas) {
    lines.push(`  ${schemaDef.schemaName}: ${schemaDef.schemaName},`)
  }
  lines.push('} as const')
  lines.push('')

  fs.mkdirSync(path.dirname(outputPath), {recursive: true})
  fs.writeFileSync(outputPath, `${lines.join('\n')}\n`, 'utf8')
}

generate()
