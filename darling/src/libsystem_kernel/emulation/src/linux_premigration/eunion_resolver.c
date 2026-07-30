#include <linux_premigration/eunion_resolver.h>

#include <string.h>

static int eunion_join(const char* root, const char* guest, char* out, size_t cap)
{
	size_t root_len = strlen(root);
	size_t guest_len = strlen(guest);

	if (root_len + guest_len + 1 > cap)
		return -1;
	memcpy(out, root, root_len);
	memcpy(out + root_len, guest, guest_len + 1);
	return 0;
}

static int eunion_parent(const char* guest, char* out, size_t cap)
{
	size_t length = strlen(guest);

	while (length > 1 && guest[length - 1] != '/')
		length--;
	if (length <= 1)
		return 0;
	length--;
	if (length + 1 > cap)
		return -1;
	memcpy(out, guest, length);
	out[length] = '\0';
	return 1;
}

int eunion_guest_path_from_host(const struct eunion_resolver* resolver,
	const char* host_path, char* guest_path, size_t guest_path_cap)
{
	const char* roots[2];
	const char* selected = NULL;
	size_t selected_len = 0;

	if (!resolver || !host_path || !guest_path || guest_path_cap == 0 ||
		!resolver->upper_root)
		return -1;
	roots[0] = resolver->upper_root;
	roots[1] = resolver->lower_root;
	for (size_t index = 0; index < sizeof(roots) / sizeof(roots[0]); ++index)
	{
		if (!roots[index])
			continue;
		size_t root_len = strlen(roots[index]);
		if (root_len == 0 || strncmp(host_path, roots[index], root_len) != 0)
			continue;
		if (host_path[root_len] != '\0' && host_path[root_len] != '/')
			continue;
		if (root_len > selected_len)
		{
			selected = roots[index];
			selected_len = root_len;
		}
	}
	if (!selected)
		return 1;

	const char* suffix = host_path + selected_len;
	if (*suffix == '\0')
	{
		if (guest_path_cap < 2)
			return -1;
		guest_path[0] = '/';
		guest_path[1] = '\0';
		return 0;
	}
	if (strlen(suffix) + 1 > guest_path_cap)
		return -1;
	strcpy(guest_path, suffix);
	return 0;
}

int eunion_resolve_path(const struct eunion_resolver* resolver,
	const char* guest_path, struct eunion_resolver_result* result)
{
	char upper[EUNION_RESOLVER_PATH_MAX];
	char lower[EUNION_RESOLVER_PATH_MAX];
	char parent[EUNION_RESOLVER_PATH_MAX];
	int status;

	if (!resolver || !guest_path || guest_path[0] != '/' || !result ||
		!resolver->upper_root || !resolver->lower_root ||
		!resolver->ops.path_status || !resolver->ops.marker_status)
		return -1;
	if (eunion_join(resolver->upper_root, guest_path, upper, sizeof(upper)) != 0 ||
		eunion_join(resolver->lower_root, guest_path, lower, sizeof(lower)) != 0)
		return -1;

	status = resolver->ops.path_status(resolver->context, upper);
	if (status == 0)
	{
		status = resolver->ops.marker_status(resolver->context, upper,
			resolver->whiteout_marker);
		if (status < 0)
		{
			result->layer = EUNION_RESOLVER_ERROR;
			result->error = status;
			strcpy(result->host_path, upper);
			return 0;
		}
		if (status > 0)
		{
			result->layer = EUNION_RESOLVER_WHITEOUT;
			strcpy(result->host_path, upper);
			result->error = resolver->missing_status;
			return 0;
		}
		result->layer = EUNION_RESOLVER_UPPER;
		strcpy(result->host_path, upper);
		result->error = 0;
		return 0;
	}
	if (status != resolver->missing_status)
	{
		result->layer = EUNION_RESOLVER_ERROR;
		result->error = status;
		strcpy(result->host_path, upper);
		return 0;
	}
	/*
	 * An external sidecar whiteout intentionally has no upper placeholder.
	 * Marker backends must therefore be consulted after an absent upper lookup
	 * as well. The legacy xattr backend still returns false for an absent path.
	 */
	status = resolver->ops.marker_status(resolver->context, upper,
		resolver->whiteout_marker);
	if (status < 0)
	{
		result->layer = EUNION_RESOLVER_ERROR;
		result->error = status;
		strcpy(result->host_path, upper);
		return 0;
	}
	if (status > 0)
	{
		result->layer = EUNION_RESOLVER_WHITEOUT;
		strcpy(result->host_path, upper);
		result->error = resolver->missing_status;
		return 0;
	}

	status = eunion_parent(guest_path, parent, sizeof(parent));
	if (status < 0)
		return -1;
	if (status > 0)
	{
		char upper_parent[EUNION_RESOLVER_PATH_MAX];
		if (eunion_join(resolver->upper_root, parent, upper_parent,
			sizeof(upper_parent)) != 0)
			return -1;
		status = resolver->ops.path_status(resolver->context, upper_parent);
		if (status != 0 && status != resolver->missing_status)
		{
			result->layer = EUNION_RESOLVER_ERROR;
			result->error = status;
			strcpy(result->host_path, upper);
			return 0;
		}
		if (status == 0)
		{
			status = resolver->ops.marker_status(resolver->context, upper_parent,
				resolver->opaque_marker);
			if (status < 0)
			{
				result->layer = EUNION_RESOLVER_ERROR;
				result->error = status;
				strcpy(result->host_path, upper);
				return 0;
			}
			if (status > 0)
			{
				result->layer = EUNION_RESOLVER_MISSING;
				strcpy(result->host_path, upper);
				result->error = resolver->missing_status;
				return 0;
			}
			if (resolver->ops.path_kind)
			{
				int kind = resolver->ops.path_kind(resolver->context, upper_parent);
				if (kind < 0)
				{
					result->layer = EUNION_RESOLVER_ERROR;
					result->error = kind;
					strcpy(result->host_path, upper);
					return 0;
				}
				if (kind == EUNION_RESOLVER_NON_DIRECTORY)
				{
					result->layer = EUNION_RESOLVER_ERROR;
					result->error = resolver->not_directory_status;
					strcpy(result->host_path, upper);
					return 0;
				}
			}
		}
	}

	status = resolver->ops.path_status(resolver->context, lower);
	if (status == 0)
	{
		result->layer = EUNION_RESOLVER_LOWER;
		strcpy(result->host_path, lower);
		result->error = 0;
		return 0;
	}
	if (status == resolver->missing_status)
	{
		result->layer = EUNION_RESOLVER_MISSING;
		strcpy(result->host_path, upper);
		result->error = status;
		return 0;
	}

	result->layer = EUNION_RESOLVER_ERROR;
	result->error = status;
	strcpy(result->host_path, lower);
	return 0;
}
