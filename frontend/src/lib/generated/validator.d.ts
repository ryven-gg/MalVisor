interface ValidationError { instancePath: string }
declare function validate(data: unknown): boolean
declare namespace validate { let errors: ValidationError[] | null }
export default validate
