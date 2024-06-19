package com.linkedin.metadata.search.utils;

import static com.datahub.authorization.AuthUtil.VIEW_RESTRICTED_ENTITY_TYPES;
import static com.linkedin.metadata.authorization.PoliciesConfig.VIEW_ENTITY_PAGE_PRIVILEGE;
import static com.linkedin.metadata.utils.SearchUtil.ES_INDEX_FIELD;
import static com.linkedin.metadata.utils.SearchUtil.KEYWORD_SUFFIX;

import com.datahub.authentication.Authentication;
import com.datahub.authorization.AuthUtil;
import com.datahub.plugins.auth.authorization.Authorizer;
import com.linkedin.common.urn.Urn;
import com.linkedin.data.template.StringArray;
import com.linkedin.metadata.aspect.AspectRetriever;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.metadata.models.registry.EntityRegistry;
import com.linkedin.metadata.search.SearchEntity;
import com.linkedin.metadata.search.SearchResult;
import com.linkedin.metadata.timeseries.elastic.indexbuilder.MappingsBuilder;
import com.linkedin.policy.DataHubActorFilter;
import com.linkedin.policy.DataHubPolicyInfo;
import com.linkedin.policy.PolicyMatchCriterion;
import com.linkedin.policy.PolicyMatchCriterionArray;
import io.datahubproject.metadata.context.ActorContext;
import io.datahubproject.metadata.context.OperationContext;
import io.datahubproject.metadata.services.RestrictedService;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;

@Slf4j
public class ESAccessControlUtil {
  private ESAccessControlUtil() {}

  private static final String OWNER_TYPES_FIELD = "ownerTypes";
  private static final QueryBuilder MATCH_ALL = QueryBuilders.matchAllQuery();

  /**
   * Given an OperationContext and SearchResult, mark the restricted entities. Currently, the entire
   * entity is marked as restricted using the key aspect name.
   *
   * @param searchResult restricted search result
   */
  public static void restrictSearchResult(
      @Nonnull OperationContext opContext, @Nonnull SearchResult searchResult) {
    restrictSearchResult(opContext, searchResult.getEntities());
  }

  public static Collection<SearchEntity> restrictSearchResult(
      @Nonnull OperationContext opContext, Collection<SearchEntity> searchEntities) {
    if (opContext.getOperationContextConfig().getViewAuthorizationConfiguration().isEnabled()
        && !opContext.isSystemAuth()) {
      final EntityRegistry entityRegistry = Objects.requireNonNull(opContext.getEntityRegistry());
      final RestrictedService restrictedService =
          Objects.requireNonNull(opContext.getServicesRegistryContext()).getRestrictedService();
      final Authentication auth = opContext.getSessionActorContext().getAuthentication();
      final Authorizer authorizer = opContext.getAuthorizerContext().getAuthorizer();

      if (opContext.getSearchContext().isRestrictedSearch()) {
        for (SearchEntity searchEntity : searchEntities) {
          final String entityType = searchEntity.getEntity().getEntityType();
          final com.linkedin.metadata.models.EntitySpec entitySpec =
              entityRegistry.getEntitySpec(entityType);

          if (VIEW_RESTRICTED_ENTITY_TYPES.contains(entityType)
              && !AuthUtil.canViewEntity(
                  auth.getActor().toUrnStr(), authorizer, searchEntity.getEntity())) {

            // Not authorized && restricted response requested
            if (opContext.getSearchContext().isRestrictedSearch()) {
              // Restrict entity
              searchEntity.setRestrictedAspects(
                  new StringArray(List.of(entitySpec.getKeyAspectName())));

              searchEntity.setEntity(
                  restrictedService.encryptRestrictedUrn(searchEntity.getEntity()));
            }
          }
        }
      }
    }
    return searchEntities;
  }

  public static boolean restrictUrn(@Nonnull OperationContext opContext, @Nonnull Urn urn) {
    if (opContext.getOperationContextConfig().getViewAuthorizationConfiguration().isEnabled()
        && !opContext.isSystemAuth()) {
      final Authentication auth = opContext.getSessionActorContext().getAuthentication();
      final Authorizer authorizer = opContext.getAuthorizerContext().getAuthorizer();
      return !AuthUtil.canViewEntity(auth.getActor().toUrnStr(), authorizer, urn);
    }
    return false;
  }

  /**
   * Given the OperationContext produce a filter for search results
   *
   * @param opContext the OperationContext of the search
   * @return
   */
  public static Optional<QueryBuilder> buildAccessControlFilters(
      @Nonnull OperationContext opContext) {
    Optional<QueryBuilder> response = Optional.empty();

    /*
     If search authorization is enabled AND we're also not the system performing the query
    */
    if (opContext.getOperationContextConfig().getViewAuthorizationConfiguration().isEnabled()
        && !opContext.isSystemAuth()
        && !opContext.getSearchContext().isRestrictedSearch()) {

      BoolQueryBuilder builder = QueryBuilders.boolQuery();

      // Apply access policies
      streamViewQueries(opContext).distinct().forEach(builder::should);

      if (builder.should().isEmpty()) {
        // default no filters
        return Optional.of(builder.mustNot(MATCH_ALL));
      } else if (!builder.should().contains(MATCH_ALL)) {
        // if MATCH_ALL is not present, apply filters requiring at least 1
        builder.minimumShouldMatch(1);
        response = Optional.of(builder);
      }
    }

    // MATCH_ALL filter present or system user or disabled
    return response;
  }

  private static final Function<DataHubPolicyInfo, Boolean> activeMetadataViewEntityPolicyFilter =
      policy ->
          policy.getPrivileges() != null
              && PoliciesConfig.ACTIVE_POLICY_STATE.equals(policy.getState())
              && PoliciesConfig.METADATA_POLICY_TYPE.equals(policy.getType())
              && policy.getPrivileges().contains(VIEW_ENTITY_PAGE_PRIVILEGE.getType());

  private static Stream<QueryBuilder> streamViewQueries(OperationContext opContext) {
    return opContext.getSessionActorContext().getPolicyInfoSet().stream()
        .filter(activeMetadataViewEntityPolicyFilter::apply)
        .map(
            policy -> {
              // Build actor query
              QueryBuilder actorQuery = buildActorQuery(opContext, policy);

              if (!policy.hasResources()) {
                // no resource restrictions
                return actorQuery;
              } else {

                // No filters or criteria
                if (!policy.getResources().hasFilter()
                    || !policy.getResources().getFilter().hasCriteria()) {
                  return null;
                }

                PolicyMatchCriterionArray criteriaArray =
                    policy.getResources().getFilter().getCriteria();
                // Cannot apply policy if we can't map every field
                if (!criteriaArray.stream()
                    .allMatch(
                        criteria ->
                            toESField(criteria, opContext.getAspectRetriever()).isPresent())) {
                  return null;
                }

                BoolQueryBuilder resourceQuery = QueryBuilders.boolQuery();
                // apply actor filter if present
                if (!MATCH_ALL.equals(actorQuery)) {
                  resourceQuery.filter(actorQuery);
                }
                // add resource query
                buildResourceQuery(opContext, criteriaArray).forEach(resourceQuery::filter);
                return resourceQuery;
              }
            })
        .filter(Objects::nonNull);
  }

  /**
   * Build an entity index query for ownership policies. If no restrictions, returns MATCH_ALL query
   *
   * @param opContext context
   * @param policy policy
   * @return filter query
   */
  private static QueryBuilder buildActorQuery(
      OperationContext opContext, DataHubPolicyInfo policy) {
    DataHubActorFilter actorFilter = policy.getActors();

    if (!policy.hasActors()
        || !(actorFilter.isResourceOwners() || actorFilter.hasResourceOwnersTypes())) {
      // no owner restriction
      return MATCH_ALL;
    }

    ActorContext actorContext = opContext.getSessionActorContext();

    // policy might apply to the actor via user or group
    List<String> actorAndGroupUrns =
        Stream.concat(
                Stream.of(actorContext.getAuthentication().getActor().toUrnStr()),
                actorContext.getGroupMembership().stream().map(Urn::toString))
            .map(String::toLowerCase)
            .distinct()
            .collect(Collectors.toList());

    if (!actorFilter.hasResourceOwnersTypes()) {
      // owners without owner type restrictions
      return QueryBuilders.termsQuery(
          ESUtils.toKeywordField(
              MappingsBuilder.OWNERS_FIELD, false, opContext.getAspectRetriever()),
          actorAndGroupUrns);
    } else {
      // owners with type restrictions
      BoolQueryBuilder orQuery = QueryBuilders.boolQuery();
      orQuery.minimumShouldMatch(1);

      Set<String> typeFields =
          actorFilter.getResourceOwnersTypes().stream()
              .map(
                  typeUrn ->
                      String.format(
                          "%s.%s%s",
                          OWNER_TYPES_FIELD, encodeFieldName(typeUrn.toString()), KEYWORD_SUFFIX))
              .collect(Collectors.toSet());

      typeFields.forEach(
          field -> orQuery.should(QueryBuilders.termsQuery(field, actorAndGroupUrns)));

      return orQuery;
    }
  }

  private static Stream<TermsQueryBuilder> buildResourceQuery(
      OperationContext opContext, PolicyMatchCriterionArray criteriaArray) {
    return criteriaArray.stream()
        .map(
            criteria ->
                QueryBuilders.termsQuery(
                    toESField(criteria, opContext.getAspectRetriever()).get(),
                    toESValues(opContext, criteria)));
  }

  private static Optional<String> toESField(
      PolicyMatchCriterion criterion, AspectRetriever aspectRetriever) {
    switch (criterion.getField()) {
      case "TYPE":
        return Optional.of(ES_INDEX_FIELD);
      case "URN":
        return Optional.of(
            ESUtils.toKeywordField(MappingsBuilder.URN_FIELD, false, aspectRetriever));
      case "TAG":
        return Optional.of(
            ESUtils.toKeywordField(MappingsBuilder.TAGS_FIELD, false, aspectRetriever));
      case "DOMAIN":
        return Optional.of(
            ESUtils.toKeywordField(MappingsBuilder.DOMAINS_FIELD, false, aspectRetriever));
      default:
        return Optional.empty();
    }
  }

  private static Collection<String> toESValues(
      OperationContext opContext, PolicyMatchCriterion criterion) {
    switch (criterion.getField()) {
      case "TYPE":
        return criterion.getValues().stream()
            .map(
                value ->
                    opContext.getSearchContext().getIndexConvention().getEntityIndexName(value))
            .collect(Collectors.toSet());
      default:
        return criterion.getValues();
    }
  }

  public static String encodeFieldName(String value) {
    return value.replaceAll("[.]", "%2E");
  }
}
