import {DbRepositoryError} from './errors.js'
import {AdminAuthRepository} from './repositories/adminAuthRepository.js'
import {ApprovalRequestRepository} from './repositories/approvalRequestRepository.js'
import {AuditEventRepository} from './repositories/auditEventRepository.js'
import {EnrollmentTokenRepository} from './repositories/enrollmentTokenRepository.js'
import {IntegrationRepository} from './repositories/integrationRepository.js'
import {PolicyRuleRepository} from './repositories/policyRuleRepository.js'
import {SecretRepository} from './repositories/secretRepository.js'
import {SessionRepository} from './repositories/sessionRepository.js'
import {TemplateRepository} from './repositories/templateRepository.js'
import {TenantRepository} from './repositories/tenantRepository.js'
import {UserRepository} from './repositories/userRepository.js'
import {WorkloadRepository} from './repositories/workloadRepository.js'
import type {DatabaseClient, RepositoryOperationContext} from './types.js'
import {resolveRepositoryDbClient} from './utils.js'

export type DbRepositories = {
  adminAuthRepository: AdminAuthRepository
  tenantRepository: TenantRepository
  userRepository: UserRepository
  workloadRepository: WorkloadRepository
  enrollmentTokenRepository: EnrollmentTokenRepository
  sessionRepository: SessionRepository
  integrationRepository: IntegrationRepository
  secretRepository: SecretRepository
  templateRepository: TemplateRepository
  policyRuleRepository: PolicyRuleRepository
  approvalRequestRepository: ApprovalRequestRepository
  auditEventRepository: AuditEventRepository
}

export const createDbRepositories = (dbClient: DatabaseClient): DbRepositories => ({
  adminAuthRepository: new AdminAuthRepository(dbClient),
  tenantRepository: new TenantRepository(dbClient),
  userRepository: new UserRepository(dbClient),
  workloadRepository: new WorkloadRepository(dbClient),
  enrollmentTokenRepository: new EnrollmentTokenRepository(dbClient),
  sessionRepository: new SessionRepository(dbClient),
  integrationRepository: new IntegrationRepository(dbClient),
  secretRepository: new SecretRepository(dbClient),
  templateRepository: new TemplateRepository(dbClient),
  policyRuleRepository: new PolicyRuleRepository(dbClient),
  approvalRequestRepository: new ApprovalRequestRepository(dbClient),
  auditEventRepository: new AuditEventRepository(dbClient)
})

export const runInTransaction = async <T>(
  dbClient: DatabaseClient,
  operation: (transactionClient: DatabaseClient) => Promise<T>,
  context?: RepositoryOperationContext
): Promise<T> => {
  if (context?.transaction_client !== undefined) {
    const transactionClient = resolveRepositoryDbClient(dbClient, context, [])
    return operation(transactionClient)
  }

  if (typeof dbClient.$transaction !== 'function') {
    throw new DbRepositoryError(
      'dependency_missing',
      'Database client must provide transactional execution when no transaction_client is supplied'
    )
  }

  return dbClient.$transaction(transactionClient => operation(transactionClient))
}
