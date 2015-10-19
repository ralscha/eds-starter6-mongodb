package ch.rasc.eds.starter.util;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.mongodb.morphia.query.Query;

import ch.ralscha.extdirectspring.bean.ExtDirectStoreReadRequest;
import ch.ralscha.extdirectspring.bean.SortDirection;
import ch.ralscha.extdirectspring.bean.SortInfo;

public abstract class QueryUtil {


	public static void applySortAndPageing(Query<?> query,
			ExtDirectStoreReadRequest request) {

		List<String> orders = new ArrayList<>();
		for (SortInfo sortInfo : request.getSorters()) {

			if (sortInfo.getDirection() == SortDirection.ASCENDING) {
				orders.add(sortInfo.getProperty());
			}
			else {
				orders.add("-" + sortInfo.getProperty());
			}
		}

		if (!orders.isEmpty()) {
			query.order(orders.stream().collect(Collectors.joining(",")));
		}

		System.out.println("LIMIT: " + request.getLimit());
		System.out.println("START: " + request.getStart());
		System.out.println("PAGE : " + request.getPage());
		if (request.getLimit() > 0) {
			query.offset(request.getStart()).limit(request.getLimit());
		}
	}

}